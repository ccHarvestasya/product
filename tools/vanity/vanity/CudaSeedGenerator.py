import hashlib
from pathlib import Path

from mnemonic import Mnemonic


def prepare_hmac_keys(mnemonics):
	"""Encodes normalized BIP39 passwords as SHA512 HMAC key blocks."""

	keys = bytearray()
	for mnemonic in mnemonics:
		password = Mnemonic.normalize_string(mnemonic).encode('utf8')
		if len(password) > 128:
			password = hashlib.sha512(password).digest()
		keys.extend(password.ljust(128, b'\0'))
	return keys


class CudaSeedGenerator:
	"""Batched BIP39 PBKDF2-HMAC-SHA512 with an empty passphrase on NVIDIA CUDA."""

	def __init__(self, device_id=0):
		try:
			import cupy  # pylint: disable=import-outside-toplevel
			import numpy  # pylint: disable=import-outside-toplevel
		except ImportError as ex:
			raise RuntimeError('CUDA backend requires CuPy; see README.md for installation instructions') from ex

		self.cupy = cupy
		self.numpy = numpy
		try:
			self.device = cupy.cuda.Device(device_id)
			with self.device:
				source = Path(__file__).with_name('bip39.cu').read_text(encoding='utf8')
				self.kernel = cupy.RawKernel(source, 'bip39_seeds', options=('--std=c++11',))
				self.kernel.compile()
				# Check both short and hashed HMAC passwords before searching with this device.
				mnemonics = [Mnemonic('english').to_mnemonic(bytes(size)) for size in (16, 32)]
				if self.generate(mnemonics) != [Mnemonic.to_seed(mnemonic, '') for mnemonic in mnemonics]:
					raise RuntimeError('CUDA seed self-test failed')
		except Exception as ex:
			raise RuntimeError(f'Cannot initialize CUDA device {device_id}: {ex}') from ex

	def generate(self, mnemonics):
		"""Returns one 64-byte seed per mnemonic, in input order."""

		if not mnemonics:
			return []

		with self.device:
			keys = self.cupy.asarray(self.numpy.frombuffer(prepare_hmac_keys(mnemonics), dtype=self.numpy.uint8))
			seeds = self.cupy.empty((len(mnemonics), 64), dtype=self.cupy.uint8)
			try:
				self.kernel(((len(mnemonics) + 127) // 128,), (128,), (keys, seeds, self.numpy.uint32(len(mnemonics))))
				seed_bytes = seeds.get().tobytes()  # pylint: disable=no-member
			finally:
				# CuPy pools device allocations; erase their contents before returning them to the pool.
				keys.fill(0)
				seeds.fill(0)
				self.cupy.cuda.get_current_stream().synchronize()
		return [seed_bytes[offset:offset + 64] for offset in range(0, len(seed_bytes), 64)]
