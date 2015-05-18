import os
import tempfile
import unittest

from node import db_store, setup_db


class TestDbOperations(unittest.TestCase):
    """Test DB operations in an unencrypted DB."""

    disable_sqlite_crypt = True

    @classmethod
    def setup_path(cls):
        cls.db_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.db_dir, 'testdb.db')

    @classmethod
    def setup_db(cls):
        setup_db.setup_db(
            cls.db_path,
            disable_sqlite_crypt=cls.disable_sqlite_crypt
        )

    @classmethod
    def setUpClass(cls):
        cls.setup_path()
        cls.setup_db()

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.db_path)
        os.rmdir(cls.db_dir)

    def setUp(self):
        self.db = db_store.Obdb(
            self.db_path,
            disable_sqlite_crypt=self.disable_sqlite_crypt
        )

    def test_insert_select_operations(self):
        # Create a dictionary of a random review
        review_to_store = {"pubKey": "123",
                           "subject": "A review",
                           "signature": "a signature",
                           "text": "Very happy to be a customer.",
                           "rating": 10}

        # Use the insert operation to add it to the db
        self.db.insert_entry("reviews", review_to_store)

        # Try to retrieve the record we just added based on the pubkey
        retrieved_review = self.db.select_entries("reviews", {"pubkey": "123"})

        # The above statement will return a list with all the
        # retrieved records as dictionaries
        self.assertEqual(len(retrieved_review), 1)
        retrieved_review = retrieved_review[0]

        # Is the retrieved record the same as the one we added before?
        self.assertEqual(
            review_to_store["pubKey"],
            retrieved_review["pubKey"],
        )
        self.assertEqual(
            review_to_store["subject"],
            retrieved_review["subject"],
        )
        self.assertEqual(
            review_to_store["signature"],
            retrieved_review["signature"],
        )
        self.assertEqual(
            review_to_store["text"],
            retrieved_review["text"],
        )
        self.assertEqual(
            review_to_store["rating"],
            retrieved_review["rating"],
        )

        # Let's do it again with a malicious review.
        review_to_store = {"pubKey": "321",
                           "subject": "Devil''''s review",
                           "signature": "quotes\"\"\"\'\'\'",
                           "text": 'Very """"happy"""""" to be a customer.',
                           "rating": 10}

        # Use the insert operation to add it to the db
        self.db.insert_entry("reviews", review_to_store)

        # Try to retrieve the record we just added based on the pubkey
        retrieved_review = self.db.select_entries("reviews", {"pubkey": "321"})

        # The above statement will return a list with all the
        # retrieved records as dictionaries
        self.assertEqual(len(retrieved_review), 1)
        retrieved_review = retrieved_review[0]

        # Is the retrieved record the same as the one we added before?
        self.assertEqual(
            review_to_store["pubKey"],
            retrieved_review["pubKey"],
        )
        self.assertEqual(
            review_to_store["subject"],
            retrieved_review["subject"],
        )
        self.assertEqual(
            review_to_store["signature"],
            retrieved_review["signature"],
        )
        self.assertEqual(
            review_to_store["text"],
            retrieved_review["text"],
        )
        self.assertEqual(
            review_to_store["rating"],
            retrieved_review["rating"],
        )

        # By ommiting the second parameter, we are retrieving all reviews
        all_reviews = self.db.select_entries("reviews")
        self.assertEqual(len(all_reviews), 2)

        # Use the <> operator. This should return the review with pubKey 123.
        retrieved_review = self.db.select_entries(
            "reviews",
            {"pubkey": {"value": "321", "sign": "<>"}}
        )
        self.assertEqual(len(retrieved_review), 1)
        retrieved_review = retrieved_review[0]
        self.assertEqual(
            retrieved_review["pubKey"],
            "123"
        )

    def test_get_or_create_record_when_not_exists(self):
        record = {"city": "Zurich"}
        table = "settings"
        retrieved_record = self.db.get_or_create(table, record)
        self.assertEqual(retrieved_record["city"], record["city"])
        # check that the missing fields were created as empty
        self.assertEqual(retrieved_record["countryCode"], "")

    def test_update_operation(self):
        # Retrieve the record with pubkey equal to '123'
        retrieved_review = self.db.select_entries("reviews", {"pubkey": "321"})[0]

        # Check that the rating is still '10' as expected
        self.assertEqual(retrieved_review["rating"], 10)

        # Update the record with pubkey equal to '123'
        # and lower its rating to 9
        self.db.update_entries("reviews", {"rating": 9}, {"pubkey": "123"})

        # Retrieve the same record again
        retrieved_review = self.db.select_entries("reviews", {"pubkey": "123"})[0]

        # Test that the rating has been updated succesfully
        self.assertEqual(retrieved_review["rating"], 9)

    def test_delete_operation(self):
        # Delete the entry with pubkey equal to '123'
        self.db.delete_entries("reviews", {"pubkey": "123"})

        # Looking for this record with will bring nothing
        retrieved_review = self.db.select_entries("reviews", {"pubkey": "123"})
        self.assertEqual(len(retrieved_review), 0)


class TestCryptDbOperations(TestDbOperations):
    """Test DB operations in an encrypted DB."""

    disable_sqlite_crypt = False

if __name__ == '__main__':
    unittest.main()
