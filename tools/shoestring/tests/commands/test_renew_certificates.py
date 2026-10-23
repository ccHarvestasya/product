import os
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.PrivateKeyStorage import PrivateKeyStorage

from shoestring.__main__ import main
from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.internal.PemUtils import read_public_key_from_private_key_pem_file, read_public_key_from_public_key_pem_file
from shoestring.internal.Preparer import Preparer
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration

from ..test.CertificateTestUtils import assert_certificate_matches_host, assert_certificate_properties, create_openssl_executor
from ..test.ConfigurationTestUtils import prepare_shoestring_configuration

# pylint: disable=invalid-name


# region node certificate renewal only

def _create_configuration(output_directory, ca_password, ca_common_name, node_common_name, filename):
	return prepare_shoestring_configuration(
		output_directory,
		NodeFeatures.PEER,
		ca_password=ca_password,
		ca_common_name=ca_common_name,
		node_common_name=node_common_name,
		filename=filename)


def _load_binary_file_data(filename):
	with open(filename, 'rb') as infile:
		return infile.read()


def _assert_node_full_certificate(ca_certificate_filepath, node_certificate_filepath, certificates_path):
	node_full_crt_data = _load_binary_file_data(certificates_path / 'node.full.crt.pem')
	node_crt_data = _load_binary_file_data(node_certificate_filepath)
	ca_crt_data = _load_binary_file_data(ca_certificate_filepath)
	assert node_full_crt_data == node_crt_data + ca_crt_data


async def _assert_can_renew_node_certificate(ca_password=None, retain_key=False, use_relative_path=False, force=False):
	# pylint: disable=too-many-locals

	# Arrange:
	if use_relative_path and not force:
		# Set the temp directory to cwd so that temp and relative paths are resolved to the same filesystem.
		# If install path and temp are on different filesystem device then --force has to be used.
		tempfile.tempdir = os.getcwd()

	with tempfile.TemporaryDirectory() as output_directory:
		config_filepath_1 = _create_configuration(output_directory, ca_password, 'ORIGINAL CA CN', 'ORIGINAL NODE CN', '1.shoestring.ini')
		config_filepath_2 = _create_configuration(output_directory, ca_password, 'ORIGINAL CA CN', 'NEW NODE CN', '2.shoestring.ini')
		preparer = Preparer(output_directory, parse_shoestring_configuration(config_filepath_1))

		# - generate CA private key pem file
		ca_private_key = PrivateKey.random()
		private_key_storage = PrivateKeyStorage(output_directory, ca_password)
		private_key_storage.save('ca.key', ca_private_key)

		# - generate initial set of certificates
		#   in order for node certificate to be verifiable, CA must have same issuer and subject
		ca_key_path = Path(output_directory) / 'ca.key.pem'
		preparer.directories.certificates.mkdir(parents=True)
		preparer.generate_certificates(ca_key_path, require_ca=True)

		# - save last modified times
		ca_certificate_path = preparer.directories.certificates / 'ca.crt.pem'
		ca_certificate_last_modified_time = ca_certificate_path.stat().st_mtime

		node_certificate_path = preparer.directories.certificates / 'node.crt.pem'
		node_certificate_last_modified_time = node_certificate_path.stat().st_mtime

		node_key_path = preparer.directories.certificates / 'node.key.pem'
		node_key_data = _load_binary_file_data(node_key_path)

		node_path = Path(output_directory) if not use_relative_path else Path(output_directory).relative_to(os.getcwd())

		# Sanity:
		assert_certificate_properties(node_certificate_path, 'ORIGINAL CA CN', 'ORIGINAL NODE CN', 375)
		assert_certificate_properties(ca_certificate_path, 'ORIGINAL CA CN', 'ORIGINAL CA CN', 20 * 365)

		# Act:
		await main([
			'renew-certificates',
			'--config', str(config_filepath_2),
			'--directory', str(node_path),
			'--ca-key-path', str(ca_key_path),
			*(['--retain-node-key'] if retain_key else []),
			*(['--force'] if force else [])
		])

		# Assert: node certificate is regenerated (subject changed)
		assert_certificate_properties(node_certificate_path, 'ORIGINAL CA CN', 'NEW NODE CN', 375)
		create_openssl_executor().dispatch(['verify', '-CAfile', ca_certificate_path, node_certificate_path])
		assert node_certificate_last_modified_time != node_certificate_path.stat().st_mtime
		node_key_data_after = _load_binary_file_data(node_key_path)
		if retain_key:
			assert node_key_data == node_key_data_after
		else:
			assert node_key_data != node_key_data_after

		# - ca certificate is not regenerated
		assert_certificate_properties(ca_certificate_path, 'ORIGINAL CA CN', 'ORIGINAL CA CN', 20 * 365)
		create_openssl_executor().dispatch(['verify', '-CAfile', ca_certificate_path, ca_certificate_path])
		assert ca_certificate_last_modified_time == ca_certificate_path.stat().st_mtime

		# verify that node.full == node.crt + ca.crt
		_assert_node_full_certificate(ca_certificate_path, node_certificate_path, preparer.directories.certificates)


async def test_can_renew_node_certificate():
	await _assert_can_renew_node_certificate()


async def test_can_renew_node_certificate_with_ca_password():
	await _assert_can_renew_node_certificate('abcd')


async def test_can_renew_node_certificate_with_retain_key():
	await _assert_can_renew_node_certificate(retain_key=True)


async def test_can_renew_node_certificate_with_relative_path():
	await _assert_can_renew_node_certificate(use_relative_path=True)


async def test_can_renew_node_certificate_with_force():
	await _assert_can_renew_node_certificate(force=True)


async def test_can_renew_node_certificate_with_relative_path_and_force():
	await _assert_can_renew_node_certificate(use_relative_path=True, force=True)


@pytest.mark.parametrize('host', ['node.example.com', '127.0.0.1', '2001:db8::1'])
@pytest.mark.parametrize('renew_ca', [False, True])
async def test_renew_certificates_uses_configured_host_for_subject_alt_name(host, renew_ca):
	with tempfile.TemporaryDirectory() as directory:
		config_path = _create_configuration(directory, None, 'My CA', 'My Node old.example.com', 'shoestring.ini')
		preparer = Preparer(directory, parse_shoestring_configuration(config_path))
		preparer.create_subdirectories()
		resources_path = preparer.directories.resources / 'config-node.properties'
		resources_path.write_text('[localnode]\nhost = old.example.com\n', encoding='utf8')
		ca_key_path = Path(directory) / 'ca.key.pem'
		preparer.generate_certificates(ca_key_path, require_ca=False)
		# Keep the display CN unchanged while changing the actual endpoint before renewal.
		resources_path.write_text(f'[localnode]\nhost = {host}\n', encoding='utf8')

		await main([
			'renew-certificates', '--config', str(config_path), '--directory', directory, '--ca-key-path', str(ca_key_path),
			*(['--renew-ca'] if renew_ca else [])
		])

		assert_certificate_matches_host(
			preparer.directories.certificates / 'node.crt.pem', preparer.directories.certificates / 'ca.crt.pem', host)
		assert_certificate_properties(preparer.directories.certificates / 'node.crt.pem', 'My CA', 'My Node old.example.com', 375)
		with pytest.raises(RuntimeError):
			assert_certificate_matches_host(
				preparer.directories.certificates / 'node.crt.pem', preparer.directories.certificates / 'ca.crt.pem', 'old.example.com')

# endregion


# region CA and node certificates renewal

def _replace_ca_certificate_with_legacy_ca(ca_key_path, ca_certificate_path, ca_password):
	# Reproduce the CA extensions used before strict X.509v3 support, independently of CertificateFactory.
	with tempfile.TemporaryDirectory() as directory:
		config_path = Path(directory) / 'legacy-ca.cnf'
		config_path.write_text('\n'.join([
			'[req]',
			'prompt = no',
			'distinguished_name = dn',
			'x509_extensions = ca_extensions',
			'[dn]',
			'CN = ORIGINAL CA CN',
			'[ca_extensions]',
			'basicConstraints = critical,CA:TRUE',
			'subjectKeyIdentifier = hash',
			'authorityKeyIdentifier = keyid:always,issuer'
		]), encoding='utf8')
		ca_certificate_path.unlink()
		create_openssl_executor().dispatch([
			'req', '-new', '-x509', '-config', config_path,
			'-key', Path(ca_key_path).absolute(), '-days', str(20 * 365), '-out', ca_certificate_path
		] + (['-passin', ca_password] if ca_password else []))

	legacy_ca = x509.load_pem_x509_certificate(ca_certificate_path.read_bytes())
	with pytest.raises(x509.ExtensionNotFound):
		legacy_ca.extensions.get_extension_for_class(x509.KeyUsage)


async def _assert_can_renew_ca_and_node_certificates(
	ca_password=None, use_relative_path=None, replace_ca_key=False, force=False, legacy_ca=False
):
	# pylint: disable=too-many-locals

	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		config_filepath_1 = _create_configuration(output_directory, ca_password, 'ORIGINAL CA CN', 'ORIGINAL NODE CN', '1.shoestring.ini')
		config_filepath_2 = _create_configuration(output_directory, ca_password, 'NEW CA CN', 'NEW NODE CN', '2.shoestring.ini')
		preparer = Preparer(output_directory, parse_shoestring_configuration(config_filepath_1))

		with tempfile.TemporaryDirectory(dir=os.getcwd() if use_relative_path else None) as ca_directory:
			# - generate CA private key pem file
			ca_private_key = PrivateKey.random()
			private_key_storage = PrivateKeyStorage(ca_directory, ca_password)
			private_key_storage.save('ca.key', ca_private_key)

			# - generate initial set of certificates
			ca_key_path = (Path(ca_directory) if not use_relative_path else Path(ca_directory).relative_to(os.getcwd())) / 'ca.key.pem'
			preparer.directories.certificates.mkdir(parents=True)
			preparer.generate_certificates(Path(ca_key_path).absolute(), require_ca=True)

			# - save last modified times
			ca_certificate_path = preparer.directories.certificates / 'ca.crt.pem'
			if legacy_ca:
				_replace_ca_certificate_with_legacy_ca(ca_key_path, ca_certificate_path, preparer.config.node.ca_password)
			ca_certificate_last_modified_time = ca_certificate_path.stat().st_mtime

			node_certificate_path = preparer.directories.certificates / 'node.crt.pem'
			node_certificate_last_modified_time = node_certificate_path.stat().st_mtime

			# Sanity:
			assert_certificate_properties(node_certificate_path, 'ORIGINAL CA CN', 'ORIGINAL NODE CN', 375)
			assert_certificate_properties(ca_certificate_path, 'ORIGINAL CA CN', 'ORIGINAL CA CN', 20 * 365)

			if replace_ca_key:
				private_key_storage.save('ca.key', PrivateKey.random())

			# Act:
			await main([
				'renew-certificates',
				'--config', str(config_filepath_2),
				'--directory', output_directory,
				'--ca-key-path', str(ca_key_path),
				'--renew-ca',
				*(['--force'] if force else [])
			])

			# Assert: node certificate is regenerated (subject changed)
			assert_certificate_properties(node_certificate_path, 'NEW CA CN', 'NEW NODE CN', 375)
			create_openssl_executor().dispatch(['verify', '-x509_strict', '-CAfile', ca_certificate_path, node_certificate_path])
			assert node_certificate_last_modified_time != node_certificate_path.stat().st_mtime

			# - ca certificate is regenerated (subject changed)
			assert_certificate_properties(ca_certificate_path, 'NEW CA CN', 'NEW CA CN', 20 * 365)
			create_openssl_executor().dispatch(['verify', '-x509_strict', '-CAfile', ca_certificate_path, ca_certificate_path])
			assert ca_certificate_last_modified_time != ca_certificate_path.stat().st_mtime

			# - ca public key matches the private key used to renew the certificates
			expected_ca_public_key = read_public_key_from_private_key_pem_file(ca_key_path, preparer.config.node.ca_password)
			assert expected_ca_public_key == read_public_key_from_public_key_pem_file(
				preparer.directories.certificates / 'ca.pubkey.pem')
			if legacy_ca:
				assert ca_private_key == private_key_storage.load('ca.key')
				assert x509.load_pem_x509_certificate(ca_certificate_path.read_bytes()).extensions.get_extension_for_class(
					x509.KeyUsage).value.key_cert_sign

			# verify that node.full == node.crt + ca.crt
			_assert_node_full_certificate(ca_certificate_path, node_certificate_path, preparer.directories.certificates)


async def test_can_renew_ca_and_node_certificates():
	await _assert_can_renew_ca_and_node_certificates()


async def test_can_renew_ca_and_node_certificates_with_ca_password():
	await _assert_can_renew_ca_and_node_certificates('abcd')


@pytest.mark.parametrize('ca_password', [None, 'abcd'])
@pytest.mark.parametrize('force', [False, True])
async def test_can_renew_ca_and_node_certificates_with_new_ca_key(ca_password, force):
	await _assert_can_renew_ca_and_node_certificates(ca_password, replace_ca_key=True, force=force)


@pytest.mark.parametrize('ca_password', [None, 'abcd'])
@pytest.mark.parametrize('force', [False, True])
async def test_can_renew_legacy_ca_and_node_certificates_without_replacing_ca_key(ca_password, force):
	await _assert_can_renew_ca_and_node_certificates(ca_password, force=force, legacy_ca=True)

# endregion


# region ca key path validation

async def test_can_renew_ca_and_node_certificates_with_relative_ca_key_path():
	await _assert_can_renew_ca_and_node_certificates(use_relative_path=True)


async def test_cannot_renew_ca_and_node_certificates_when_ca_key_path_does_not_exist():
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		config_filepath_1 = _create_configuration(output_directory, None, 'ORIGINAL CA CN', 'ORIGINAL NODE CN', '1.shoestring.ini')
		config_filepath_2 = _create_configuration(output_directory, None, 'NEW CA CN', 'NEW NODE CN', '2.shoestring.ini')
		preparer = Preparer(output_directory, parse_shoestring_configuration(config_filepath_1))

		# - generate CA private key pem file
		ca_private_key = PrivateKey.random()
		private_key_storage = PrivateKeyStorage(output_directory)
		private_key_storage.save('ca.key', ca_private_key)

		# - generate initial set of certificates
		ca_key_path = Path(output_directory) / 'ca.key.pem'
		preparer.directories.certificates.mkdir(parents=True)
		preparer.generate_certificates(Path(ca_key_path).absolute(), require_ca=True)

		# Act + Assert:
		with pytest.raises(RuntimeError):
			await main([
				'renew-certificates',
				'--config', str(config_filepath_2),
				'--directory', output_directory,
				'--ca-key-path', f'{ca_key_path}.non-existent',
				'--renew-ca'
			])

# endregion
