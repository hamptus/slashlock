import os
import hmac
import gzip
import shutil
import hashlib
import tempfile

from collections import namedtuple

import argon2
from argon2._password_hasher import _ensure_bytes as ensure_bytes

from nacl.secret import SecretBox
from nacl.utils import random as random_bytes
from nacl.encoding import URLSafeBase64Encoder
from nacl.exceptions import CryptoError


SALT_LENGTH = 32
ENCRYPTED_META_LENGTH = 348
SALT_AND_METADATA_SIZE = SALT_LENGTH + ENCRYPTED_META_LENGTH

NAME_PADDING = 256
CHUNK_SIZE = 4096
ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 40

COMPRESS_NONE = 0
COMPRESS_GZIP = 1


def read_file_in_chunks(f, chunk_size=CHUNK_SIZE, start=0, stop=None):
    # Get the filesize
    f.seek(0)

    has_data = f.read(1)

    f.seek(start)

    if not has_data:
        raise Exception("Can't read an empty file")

    if stop:
        curr_position = f.tell()
        while curr_position < stop:
            data = f.read(chunk_size)

            if not data:
                break

            if len(data) < chunk_size:
                yield data[0:-32]
            elif curr_position + 32 >= stop:
                end_index = stop - (curr_position + 32)
                yield data[0:-end_index]
            else:
                yield data
            curr_position = f.tell()
        return

    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data


def pad(data, chunk_size=CHUNK_SIZE):
    ''' Pad data with random bytes based on the chunk size '''
    pad_length = chunk_size - len(data)
    # Only pad the data if it is less than the expected chunk size
    if pad_length > 0:
        data += random_bytes(pad_length)
    return data


def generate_master_key(passphrase, salt=None):
    """ Generate a passphrase from a given passphrase """

    # Use the provided salt or generate a new salt
    salt = salt or random_bytes(32)

    # Make sure the passphrase is in bytes, not unicode
    passphrase = ensure_bytes(passphrase, 'utf-8')

    # Hash the passphrase and salt
    argon_hash = argon2.low_level.hash_secret_raw(
        passphrase,
        salt,
        argon2.DEFAULT_TIME_COST,
        argon2.DEFAULT_MEMORY_COST,
        argon2.DEFAULT_PARALLELISM,
        32,
        argon2.low_level.Type.I
    )

    # Return the passphrase hash and salt
    Passphrase = namedtuple("passphrase", ["hash", "salt"])
    return Passphrase(argon_hash, salt)


def metadata_from_filepath(filepath):
    """ Returns the metadata from the file in the file path"""

    size = os.path.getsize(filepath)
    name = os.path.basename(filepath).encode('utf-8')
    name_length = len(name)

    meta = namedtuple("metadata", ["size", "name_length", "name"])
    return meta(size, name_length, name)


def metadata_to_bytes(metadata, compression=COMPRESS_GZIP, archive=False):
    """ Pack the metadata into bytes """
    md = metadata

    packed_md = md.size.to_bytes(8, byteorder="little")
    packed_md += compression.to_bytes(2, byteorder='little')
    packed_md += archive.to_bytes(2, byteorder='little')
    packed_md += md.name_length.to_bytes(8, byteorder="little")
    packed_md += pad(md.name, NAME_PADDING)

    return packed_md


def metadata_to_tuple(metadata):
    """ Unpacks the metadata from bytes into a named tuple """

    internal_key = metadata[0:32]
    size = int.from_bytes(metadata[32:40], byteorder="little")
    compress = int.from_bytes(metadata[40:42], byteorder="little")
    archive = bool(int.from_bytes(metadata[42:44], byteorder="little"))

    name_length = int.from_bytes(metadata[44:52], byteorder="little")
    name = metadata[52:52 + name_length]

    meta = namedtuple("metadata", ["size", "compression", "archive",
                                   "name_length", "name", "internal_key"])
    return meta(size, compress, archive, name_length, name, internal_key)


def encrypt_metadata(metadata, master_key, internal_key):
    """ Encrypt the metadata after prepending the internal key """
    box = SecretBox(master_key)
    nonce = random_bytes(SecretBox.NONCE_SIZE)

    return box.encrypt(internal_key + metadata, nonce)


def salt_from_filepath(filepath):
    """ Return the salt from a file based on its filepath """
    with open(filepath, 'rb') as f:
        return f.read(32)


def decrypt_metadata(metadata, master_key):
    box = SecretBox(master_key)
    md = box.decrypt(metadata)
    return md


def compress(filepath, workdir, compression):
    ''' Compresses a file and returns its new filepath '''

    filepath = os.path.abspath(filepath)
    basename = ".".join([os.path.basename(filepath), 'gz'])
    workpath = os.path.join(workdir, basename)

    with open(filepath, 'rb') as file_to_compress:
        if compression == COMPRESS_GZIP:
            with gzip.open(workpath, 'wb') as gfile:
                shutil.copyfileobj(file_to_compress, gfile)

    return workpath


def decompress(filepath, save_as):
    ''' Compresses a file and returns its new filepath '''

    filepath = os.path.abspath(filepath)

    with gzip.open(filepath, 'rb') as compressed_file:
        with open(save_as, 'wb') as decompressed_file:
            shutil.copyfileobj(compressed_file, decompressed_file)

    return save_as


def _metadata_from_locked_file(filepath, passphrase):
    """ Return metadata if the file can be unlocked. None if it cannot. """

    # Directories cannot be unlocked.
    if os.path.isdir(filepath):
        return

    with open(filepath, 'rb') as locked_file:
        # Get the salt from the encrypted file
        salt = locked_file.read(SALT_LENGTH)
        # Create the master key based on passphrase and the salt
        master_key = generate_master_key(passphrase, salt)

        # Decrpyt the metadata and pack in in a named tuple
        try:
            metadata = metadata_to_tuple(
                decrypt_metadata(
                    locked_file.read(ENCRYPTED_META_LENGTH),
                    master_key.hash
                )
            )
        except CryptoError:
            return

    return metadata


def is_unlockable(filepath, passphrase):
    """ Return True if the file is unlockable, False if it's not. """
    meta = _metadata_from_locked_file(filepath, passphrase)
    return meta is not None

def randomize_name():
    return URLSafeBase64Encoder.encode(random_bytes()).decode('utf-8')

def lock(filepath, passphrase, delete_src=False, save_dir=None, save_as=None, compression=COMPRESS_GZIP):  # NOQA
    '''
    Lock a file using the provided passphrase

    - filepath: path to the plaintext file
    - passphrase: the passphrase used to encrypt the file. The same is required
      to decrypt the file
    - delete_src: Delete the source file after encryption has completed
      #FIXME: Not currently implemented
    - save_dir: Where the data should be saved. Default is same directory as
      filepath
    - save_as: What to name the encrypted file. Default is a random generated
      name
    - compression: Method used for compressing prior to encrypting. Default is
      gzip. Note: It's not very useful for already compressed files such as
      compressed media (mp3, mp4)
    '''

    archive = os.path.isdir(filepath)

    # Use the master key to lock the metadata which contains the internal key
    master_key = generate_master_key(passphrase)
    internal_key = random_bytes(SecretBox.KEY_SIZE)

    # Set the save directory to save_dir or the same directory as the file
    save_dir = save_dir or os.path.dirname(os.path.abspath(filepath))

    # Set the save as file name to save_as or a random name
    save_as = save_as or randomize_name()

    # This is where the encrypted file will be stored
    outpath = os.path.join(save_dir, save_as)

    # Get the metadata for the file as bytes and set the
    #  compression / archive bytes
    metadata = metadata_to_bytes(
        metadata_from_filepath(filepath),
        compression=compression,
        archive=archive,
    )

    # Encrypt the metadata
    encrypted_metadata = encrypt_metadata(
        metadata, master_key.hash, internal_key)

    # Prepare the hmac object
    hm = hmac.new(internal_key, digestmod=hashlib.sha256)

    # Create a temp directory for use if we compress
    with tempfile.TemporaryDirectory() as workdir:

        if archive:
            archive_path = shutil.make_archive(
                os.path.join(workdir, os.path.basename(filepath)),
                'tar',
                filepath)

            filepath = archive_path

        if compression == COMPRESS_GZIP:
            filepath = compress(filepath, workdir, compression=compression)
            # Remove the archive once it has been compressed since it is
            #  longer needed.
            if archive:
                try:
                    os.remove(archive_path)
                except FileNotFoundError:
                    pass

        # Create a box for storing secrets. Shhhhhh.
        box = SecretBox(internal_key)

        with open(filepath, 'rb') as plainfile:
            with open(outpath, 'w+b') as cipherfile:
                # Write the salt used when generating the user key
                cipherfile.write(master_key.salt)
                # Write the metadata
                cipherfile.write(encrypted_metadata)

                for chunk in read_file_in_chunks(plainfile):
                    # Encrypt the chunk with a new nonce
                    echunk = box.encrypt(
                        chunk, random_bytes(SecretBox.NONCE_SIZE))
                    # Update the hmac
                    hm.update(echunk)
                    # Write the encrypted chunk
                    cipherfile.write(echunk)
                # Write the hmac
                cipherfile.write(hm.digest())


def unlock(filepath, passphrase, delete_src=False, save_dir=None, save_as=None):

    # Set the save directory to save_dir or the same directory as the file
    save_dir = save_dir or os.path.dirname(os.path.abspath(filepath))

    with open(filepath, 'rb') as locked_file:
        # Get the salt from the encrypted file
        salt = locked_file.read(SALT_LENGTH)
        # Create the master key based on passphrase and the salt
        master_key = generate_master_key(passphrase, salt)

        # Decrpyt the metadata and pack in in a named tuple
        metadata = metadata_to_tuple(
            decrypt_metadata(
                locked_file.read(ENCRYPTED_META_LENGTH),
                master_key.hash
            )
        )

        # Use this value to get the beginning of the hmac
        hmac_start = os.path.getsize(filepath) - 32
        # Get the HMAC value from the encrypted file
        locked_file.seek(hmac_start)
        locked_file_hmac = locked_file.read()

        # Set the save as file name to save_as or original name
        save_as = save_as or metadata.name.decode('utf-8')

        # Create a temporary directory to work in if the file is compressed
        with tempfile.TemporaryDirectory() as workdir:

            if metadata.compression == COMPRESS_NONE:
                outpath = os.path.join(save_dir, save_as)
            # Change the out file path if this is compressed
            elif metadata.compression == COMPRESS_GZIP:
                outpath = ".".join([os.path.join(workdir, save_as), "gz"])

            with open(outpath, 'wb') as outfile:
                # Skip the salt and metadata
                locked_file.seek(SALT_AND_METADATA_SIZE)

                cs = ENCRYPTED_CHUNK_SIZE
                start = locked_file.tell()
                stop = hmac_start

                # Get ready to calculate the HMAC
                current_hmac = hmac.new(
                    metadata.internal_key, digestmod=hashlib.sha256)

                # Create a generator that returns the encrypted file in chunks
                chunks = read_file_in_chunks(locked_file, cs, start, stop)

                # Create a secret box for decrypting
                box = SecretBox(metadata.internal_key)

                for echunk in chunks:
                    # Update the HMAC value for comparison
                    current_hmac.update(echunk)
                    # Decrypt and write the chunk
                    if echunk:
                        chunk = box.decrypt(echunk)
                        outfile.write(chunk)

            # If the file has been compressed, decompress it and save it where
            # expected
            if metadata.compression == COMPRESS_GZIP:
                if metadata.archive:
                    with tempfile.TemporaryDirectory() as tempdir:
                        arch_path = os.path.join(tempdir, save_as + '.tar')
                        decompress(outpath, arch_path)
                        save_as = os.path.join(save_dir, save_as)
                        shutil.unpack_archive(arch_path, save_as, 'tar')
                else:
                    save_as = os.path.join(save_dir, save_as)
                    decompress(outpath, save_as)

        # Raise an exception if the HMACs are invalid
        # FIXME: We should probably do more than raise an exception
        if not hmac.compare_digest(locked_file_hmac, current_hmac.digest()):
            raise Exception("HMACs don't match")


def main():
    print("This doesn't do anything yet")


if __name__ == '__main__':
    main()
