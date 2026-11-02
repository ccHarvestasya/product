import ctypes
import hashlib
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mnemonic import Mnemonic

from vanity.CudaSeedGenerator import CudaSeedGenerator, prepare_hmac_keys


class CudaKernelArithmeticTest(unittest.TestCase):
	"""Runs the actual CUDA source as C++ to check its arithmetic without a GPU."""

	@classmethod
	def setUpClass(cls):
		compiler = shutil.which('c++')
		if not compiler:
			raise unittest.SkipTest('C++ compiler is required for CUDA kernel arithmetic tests')
		cls.directory = TemporaryDirectory()  # pylint: disable=consider-using-with
		cls.addClassCleanup(cls.directory.cleanup)
		kernel_path = Path(__file__).parents[1] / 'vanity' / 'bip39.cu'
		source = Path(cls.directory.name) / 'kernel.cpp'
		source.write_text('''
#include <cstddef>
#define __constant__
#define __device__
#define __global__
struct Dimension { unsigned int x; };
Dimension blockIdx, blockDim, threadIdx;
''' + kernel_path.read_text(encoding='utf8') + '''
extern "C" void run(const unsigned char* keys, unsigned char* seeds, unsigned int count) {
	blockDim.x = 128;
	for (unsigned int i = 0; i < count + 7; ++i) {
		blockIdx.x = i / 128;
		threadIdx.x = i % 128;
		bip39_seeds(keys, seeds, count);
	}
}
''', encoding='utf8')
		library_path = Path(cls.directory.name) / 'kernel.so'
		subprocess.run([compiler, '-std=c++11', '-O2', '-shared', '-fPIC', str(source), '-o', str(library_path)], check=True)
		cls.library = ctypes.CDLL(str(library_path))
		cls.library.run.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
		cls.library.run.restype = None

	def test_matches_reference_for_password_boundaries_normalization_and_mnemonics(self):
		mnemonics = ['', 'a', 'a' * 127, 'a' * 128, 'a' * 129, 'é', 'e\u0301', 'あいうえお\u3000かきくけこ']
		factory = Mnemonic('english')
		mnemonics += [factory.to_mnemonic(bytes(size)) for size in (16, 20, 24, 28, 32)]
		mnemonics += [factory.to_mnemonic(bytes(range(size))) for size in (16, 20, 24, 28, 32)]
		# Exercise multiple blocks and the out-of-range thread guard.
		mnemonics += [f'password {index}' for index in range(130)]
		keys = prepare_hmac_keys(mnemonics)
		output = (ctypes.c_ubyte * (64 * len(mnemonics)))()
		self.library.run((ctypes.c_ubyte * len(keys)).from_buffer(keys), output, len(mnemonics))
		for index, mnemonic in enumerate(mnemonics):
			with self.subTest(index=index):
				self.assertEqual(Mnemonic.to_seed(mnemonic, ''), bytes(output[index * 64:(index + 1) * 64]))

	def test_hmac_key_preparation(self):
		self.assertEqual(b'', prepare_hmac_keys([]))
		self.assertEqual(b'a' * 128, prepare_hmac_keys(['a' * 128]))
		self.assertEqual(hashlib.sha512(b'a' * 129).digest() + bytes(64), prepare_hmac_keys(['a' * 129]))
		self.assertEqual(prepare_hmac_keys(['é']), prepare_hmac_keys(['e\u0301']))


@unittest.skipUnless('1' == os.environ.get('VANITY_TEST_CUDA'), 'set VANITY_TEST_CUDA=1 to test on an NVIDIA GPU')
class CudaDeviceTest(unittest.TestCase):
	def test_device_results_match_reference_across_batches(self):
		generator = CudaSeedGenerator(int(os.environ.get('VANITY_GPU_DEVICE', '0')))
		self.assertEqual([], generator.generate([]))
		factory = Mnemonic('english')
		for size in (1, 127, 128, 129):
			with self.subTest(size=size):
				mnemonics = [factory.to_mnemonic(index.to_bytes(32, 'big')) for index in range(size)]
				self.assertEqual([Mnemonic.to_seed(mnemonic, '') for mnemonic in mnemonics], generator.generate(mnemonics))
