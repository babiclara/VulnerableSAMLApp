import pickle

class UserProfile:
    CLASS_NAME = "deserialization.model.user_profile.UserProfile"

    def __init__(self, username, email, user_id):
        self.username = username
        self.email = email
        self.user_id = user_id
        self.password = None
        self.session_token = None

    def __reduce__(self):
        return (self.__class__, (self.username, self.email, self.user_id))

    def __str__(self):
        return f"UserProfile{{user_id={self.user_id}, username='{self.username}', email='{self.email}'}}"