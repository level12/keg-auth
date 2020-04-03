from keg_elements.db.columns import DBEnum


class AttemptType(DBEnum):
    login = "Login"
    reset = "Password Reset"

    @classmethod
    def db_name(cls):
        return "ka_attempt_types"
