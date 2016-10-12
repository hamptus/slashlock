import os
from collections import namedtuple
from nacl.utils import random as random_bytes
import uuid

import unittest
import tempfile

import slashlock


class SlashlockTests(unittest.TestCase):

    def test_pad(self):
        ''' The pad function should return data at the expected length '''

        # Create unpadded data
        data = b"test-data"
        self.assertFalse(len(data) == 32)

        # Pad the data
        padded = slashlock.pad(data, chunk_size=32)
        self.assertEqual(len(padded), 32)

        # Create long data
        long_data = data * 50

        long_padded = slashlock.pad(long_data, chunk_size=32)
        self.assertEqual(len(long_data), len(long_padded))

    def test_generate_master_key_length(self):
        '''
        The passphrase hash should be 32 bytes. The salt should be 32 bytes
        '''
        passphrase = slashlock.generate_master_key("passphrase length test")
        self.assertEqual(len(passphrase.hash), 32)
        self.assertEqual(len(passphrase.salt), 32)

    def test_generate_master_key_repeatable(self):
        '''
        The generate_master_key function should generate the same hash each
        time when the same passphrase and salt are provided
        '''

        test_passphrase = 'test-passphrase !!'
        passphrase1 = slashlock.generate_master_key(test_passphrase)

        # Generate a new passphrase using the same passhprase and salt
        passphrase2 = slashlock.generate_master_key(
            test_passphrase, salt=passphrase1.salt)

        # The passphrases should be the same
        self.assertEqual(passphrase1, passphrase2)

        # Use a random salt
        passphrase3 = slashlock.generate_master_key(test_passphrase)

        # The passphrases should be different now
        self.assertNotEqual(passphrase1, passphrase3)

    def test_metadata_from_filepath(self):
        '''
        metadata_from_filepath should get the correct metadata for the
        given file
        '''

        # Write some data to a temporary file
        with tempfile.TemporaryDirectory() as tmpdir:
            basename = 'test-metadata-from-filepath.txt'
            filename = os.path.join(tmpdir, basename)
            with open(filename, 'w') as temp:
                temp.write("a" * 500)

            metadata = slashlock.metadata_from_filepath(filename)

        self.assertEqual(metadata.size, 500)
        self.assertEqual(metadata.name_length, len(basename))
        self.assertEqual(metadata.name, basename.encode('utf-8'))


    def test_metadata_to_bytes(self):
        ''' This function should convert the metadata to bytes '''
        meta = namedtuple("metadata", ["size", "name_length", "name"])
        metadata = meta(500, 7, b"tmp.txt")

        # metadata should not be an instance of bytes
        self.assertFalse(isinstance(metadata, bytes))

        # Let's make it bytes!
        meta_bytes = slashlock.metadata_to_bytes(metadata)
        self.assertTrue(isinstance(meta_bytes, bytes))

    def test_metadata_to_tuple(self):
        '''
        This should accept bytes and return it as a named tuple
        '''

        meta = namedtuple("metadata", ["size", "name_length", "name"])
        # Get metadata as bytes
        meta_bytes = random_bytes() + slashlock.metadata_to_bytes(
            meta(500, 7, b"tmp.txt"))

        self.assertTrue(isinstance(meta_bytes, bytes))

        # Get metadata as named tuple
        meta_tuple = slashlock.metadata_to_tuple(meta_bytes)
        # Check that the values are correct
        self.assertEqual(meta_tuple.size, 500)
        self.assertEqual(meta_tuple.name_length, 7)
        self.assertEqual(meta_tuple.name, b'tmp.txt')
        self.assertEqual(meta_tuple.compression, slashlock.COMPRESS_GZIP)
        self.assertFalse(meta_tuple.archive)
        self.assertEqual(len(meta_tuple.internal_key), 32)

    # FIXME: TODO
    def test_is_unlockable_success(self):
        """ is_unlockable should return metadata if the file is locked and the
        passphrase is correct
        """
        pass

    # FIXME: TODO
    def test_is_unlockable_wrong_passphrase(self):
        """ is_unlockable should return metadata if the file is locked and the
        passphrase is correct
        """
        pass

    # FIXME: TODO
    def test_is_unlockable_file_unlocked(self):
        """ is_unlockable should return metaata if the file is locked and the
        passphrase is correct
        """
        pass

if __name__ == '__main__':
    unittest.main()
