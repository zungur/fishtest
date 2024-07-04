import unittest
from datetime import datetime, timezone

import util
from pyramid import testing

from fishtest.views import login, signup


class Create10UsersTest(unittest.TestCase):
    def setUp(self):
        self.rundb = util.get_rundb()
        self.config = testing.setUp()
        self.config.add_route("login", "/login")
        self.config.add_route("signup", "/signup")

    def tearDown(self):
        self.rundb.userdb.users.delete_many({"username": "JoeUser"})
        self.rundb.userdb.user_cache.delete_many({"username": "JoeUser"})
        self.rundb.stop()
        testing.tearDown()

    def test_create_user(self):
        request = testing.DummyRequest(
            userdb=self.rundb.userdb,
            method="POST",
            remote_addr="127.0.0.1",
            params={
                "username": "JoeUser",
                "password": "secret",
                "password2": "secret",
                "email": "joe@user.net",
                "tests_repo": "https://github.com/official-stockfish/Stockfish",
            },
        )
        response = signup(request)
        self.assertTrue("The resource was found at", response)


class Create50LoginTest(unittest.TestCase):
    def setUp(self):
        self.rundb = util.get_rundb()
        self.rundb.userdb.create_user(
            "JoeUser",
            b"O\xc5\xdf\x0cy\x99F\xe5\xf6\xf7\xb7R\x91'*\xa5\xeeRg\x89p\x88\xa2\xb2>;u\xae\x8b\xe6H\x0br\x96.,\xaf\xf4\xc0\x16\x8c\xf7\xa5X\xb4U\x12P\xd2\xc4!\x97\xbc\x89\xee2\xd0\x18\xb3FM\xd5A\x97",
            b'\x138\xe0\xa5\xec2\xc9\xeb\x1a\x02\xe6\xf1t\x1a\x8dv',
            "email@email.email",
            "https://github.com/official-stockfish/Stockfish",
        )
        self.config = testing.setUp()
        self.config.add_route("login", "/login")

    def tearDown(self):
        self.rundb.userdb.users.delete_many({"username": "JoeUser"})
        self.rundb.userdb.user_cache.delete_many({"username": "JoeUser"})
        self.rundb.stop()
        testing.tearDown()

    def test_login(self):
        # Pending user, wrong password
        request = testing.DummyRequest(
            userdb=self.rundb.userdb,
            method="POST",
            params={"username": "JoeUser", "password": "badsecret"},
        )
        response = login(request)
        self.assertTrue(
            "Invalid password for user: JoeUser" in request.session.pop_flash("error")
        )

        # Pending user, correct password
        request.params["password"] = "secret"
        login(request)
        self.assertTrue(
            "Account pending for user: JoeUser" in request.session.pop_flash("error")[0]
        )

        # Approved user, wrong password
        user = self.rundb.userdb.get_user("JoeUser")
        user["pending"] = False
        self.rundb.userdb.save_user(user)
        request.params["password"] = "badsecret"
        response = login(request)
        self.assertTrue(
            "Invalid password for user: JoeUser" in request.session.pop_flash("error")
        )

        # Approved user, correct password
        request.params["password"] = "secret"
        response = login(request)
        self.assertEqual(response.code, 302)
        self.assertTrue("The resource was found at" in str(response))

        # User is blocked, correct password
        user["blocked"] = True
        self.rundb.userdb.save_user(user)
        response = login(request)
        self.assertTrue(
            "Account blocked for user: JoeUser" in request.session.pop_flash("error")[0]
        )

        # User is unblocked, correct password
        user["blocked"] = False
        self.rundb.userdb.save_user(user)
        response = login(request)
        self.assertEqual(response.code, 302)
        self.assertTrue("The resource was found at" in str(response))

        # Invalid username, correct password
        request.params["username"] = "UserJoe"
        response = login(request)
        self.assertTrue(
            "Invalid username: UserJoe" in request.session.pop_flash("error")[0]
        )

class Create90APITest(unittest.TestCase):
    def setUp(self):
        self.rundb = util.get_rundb()
        self.run_id = self.rundb.new_run(
            "master",
            "master",
            100000,
            "100+0.01",
            "100+0.01",
            "book",
            10,
            1,
            "",
            "",
            username="travis",
            tests_repo="travis",
            start_time=datetime.now(timezone.utc),
        )
        self.rundb.userdb.user_cache.insert_one(
            {"username": "JoeUser", "cpu_hours": 12345}
        )
        self.config = testing.setUp()
        self.config.add_route("api_stop_run", "/api/stop_run")

    def tearDown(self):
        self.rundb.userdb.users.delete_many({"username": "JoeUser"})
        self.rundb.userdb.user_cache.delete_many({"username": "JoeUser"})
        self.rundb.stop()
        testing.tearDown()


if __name__ == "__main__":
    unittest.main()
