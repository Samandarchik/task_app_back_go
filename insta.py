import instaloader
import time

USERNAME = "samandar747_"

L = instaloader.Instaloader()

print("Cookie orqali login bo‘lyapti...")
L.load_session_from_file(USERNAME)

print("Profil olinmoqda...")
profile = instaloader.Profile.from_username(L.context, USERNAME)

def safe_iter_followees(profile):
    for user in profile.get_followees():
        yield user
        print("Topildi:", user.username)
        time.sleep(3)   # Juda tez so‘rov yubormaslik uchun kutish

print("Following ro‘yxati:")
following = []

for user in safe_iter_followees(profile):
    following.append(user.username)

print("\nJami following soni:", len(following))

print("\nFollowinglar ro‘yxati:")
for u in following:
    print(u)
