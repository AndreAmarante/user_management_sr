import getpass
import os

class WrongFormatException(Exception):
	pass

DATABASE = "private_users_database.txt"
USER_LOGIN_ERR_MSG = "Username or password is incorrectw!"

def create_account():
	print("-------------Creating User-------------")
	username = input("Username: ")
	password = getpass.getpass(prompt="Password: ")
	password_repeat = getpass.getpass(prompt="Repeat password: ")
	
	if len(username)<3 or len(password)<3:
		print("Username or password too short!")
	elif ":" in username:
		print("Username contains invalid characters")
	elif ":" in password:
		print("Password contains invalid characters")
	elif password != password_repeat:
		print("Passwords don't match!")
	else:
		#Valid values inserted
		db_users = []
		database_users = open(DATABASE, "r+")
		lines = database_users.readlines()
		for line in lines:
			db_user = line.split(":")[0]
			db_users.append(db_user)
		if username not in db_users:
			to_write = username + ":" + password + ":" + "0" + "\n"
			database_users.write(to_write)
			print("Username created successfully!")
		else:
			print("Username not available!")
	print("--------------------------")
	print()

def do_login():
	print("-------------Login-------------")
	username = input("Username: ")
	password = getpass.getpass(prompt="Password: ")
	
	success_in_login = False
	username_to_return = ""
	password_to_return = ""
	admin_to_return = False
	
	db_users = []
	db_passwords = []
	db_admins = []
	database_users = open(DATABASE, "r")
	lines = database_users.readlines()
	for line in lines:
		line_pieces = line.strip("\n").split(":")
		db_user = line_pieces[0]
		db_pass = line_pieces[1]
		admin = line_pieces[2]
		db_users.append(db_user)
		db_passwords.append(db_pass)
		db_admins.append(admin)
	
	if username in db_users:
		index = db_users.index(username)
		if password != db_passwords[index]:
			print(USER_LOGIN_ERR_MSG)
		else:
			admin_value = db_admins[index]
			success_in_login = True
			username_to_return = username
			password_to_return = password
			if "1" in admin_value:
				admin_to_return = True
			print("Login done successfully!")
	else:
		print(USER_LOGIN_ERR_MSG)
	print("--------------------------")
	print()
	
	return success_in_login, username_to_return, password_to_return, admin_to_return

def delete_user():
	print("-------------Deleting user-------------")
	username = input("Username of user to delete: ")
	
	db_users = []
	database_users = open(DATABASE, "r")
	lines = database_users.readlines()
	for line in lines:
		line_pieces = line.split(":")
		db_user = line_pieces[0]
		db_users.append(db_user)
	database_users.close()
	
	if username not in db_users:
		print("Username doesn't exist!")
	else:
		index = db_users.index(username)
		lines = lines[:index] + lines[index+1:]
		database_users = open(DATABASE, "w")
		for line in lines:
			database_users.write(line)
		print(username, " deleted from database!")

def make_user_admin():
	print("-------------Making user admin-------------")
	username = input("Username of user to make admin: ")
	
	db_users = []
	db_admins = []
	database_users = open(DATABASE, "r")
	lines = database_users.readlines()
	for line in lines:
		line_pieces = line.strip("\n").split(":")
		db_user = line_pieces[0]
		if(line_pieces[2]=="1"):
			db_admins.append(db_user)
		db_users.append(db_user)
	database_users.close()
	
	if username not in db_users:
		print("Username doesn't exist!")
	elif username in db_admins:
		print("User is already admin!")
	else:
		index = db_users.index(username)
		line_to_change = lines[index]
		line_to_change = line_to_change.strip("\n")
		line_to_change = line_to_change[:len(line_to_change)-1]
		line_to_change+="1\n"
		lines[index] = line_to_change
		database_users = open(DATABASE, "w")
		for line in lines:
			database_users.write(line)
		database_users.close()
		print(username, " is now admin!")

def change_my_password(username, current_password,privilege):
	result = False
	print("-------------Changing password-------------")
	password = getpass.getpass(prompt="New password: ")
	password_repeat = getpass.getpass(prompt="Repeat new password: ")
	
	if len(password)<3:
		print("New password too short")
	elif password != password_repeat:
		print("Passwords don't match!")
	elif password == current_password:
		print("Password inserted is current password!")
	elif (":" in password):
		raise WrongFormatException("Password format invalid")
	else:
		found_user = False
		database_users = open(DATABASE, "r")
		lines = database_users.readlines()
		index_count = 0
		for line in lines:
			line_pieces = line.strip("\n").split(":")
			db_user = line_pieces[0]
			if db_user == username:
				found_user = True
				line_to_change = db_user + ":" + password + ":" + line_pieces[2] + "\n"
				index_to_change = index_count
				break
			index_count+=1
		database_users.close()
		if not found_user:
			print("User not found!")
		else:
			lines[index_to_change]=line_to_change
			database_users = open(DATABASE, "w")
			for line in lines:
				database_users.write(line)
			database_users.close()
			print("Password changed successfully!")
			result = True
	
	return result, password

if __name__ == "__main__":
	
	option = "-1"
	list_of_options = ["0","1","2","3","4","5","6"]
	list_of_privileged_options = []
	
	print("-------------Welcome-------------")
	print("-------Management Platform-------")
	
	current_available_options = []
	logged_user = ""
	logged_user_pass = ""
	login = False
	privilege_granted = False #True for admins or temporarily for any user in the process of change password
	not_leave = True
	while(not_leave):
		while option not in list_of_options:
			
			if login:
				if privilege_granted:
					print("------Admin Options------")
					print("Create account - 1")
					print("Change my password - 3")
					print("Logout - 4")
					print("Delete a user - 5")
					print("Make user admin - 6")
					current_available_options = ["0","1","3","4","5","6"]
				else:
					print("------Options------")
					print("Change my password - 3")
					print("Logout - 4")
					current_available_options = ["0","3","4"]
			else:
				print("------Options------")
				print("Create account - 1")
				print("Login - 2")
				current_available_options = ["0","1","2"]
			print("Leave - 0")
			option = input("Selected option: ")
			print()
		
		if option not in current_available_options:
			print("Option not currently available")
		elif option == "0":
			print("Bye!")
			not_leave = False
		elif option == "1":
			create_account()
		elif option == "2":
			success, username, password_logged_user, admin = do_login()
			if success:
				login = True
				logged_user = username
				logged_user_pass = password_logged_user
				privilege_granted = admin
				print("Welcome ", logged_user, "!")
		elif option == "3":
			password = getpass.getpass(prompt="Current password: ")
			if password != logged_user_pass:
				print("Incorrect password!")
			else:
				if not privilege_granted:
					try:
						# Raise privilege
						privilege_granted = True
						success, new_pass = change_my_password(logged_user,logged_user_pass,privilege_granted)
						# Lower privilege
						privilege_granted = False
					except WrongFormatException as e:
						success = False
						print("Exception generated: ", e)
						# Lower privilege to prevent privilieges management vulnerability
						privilege_granted = False
						
				else:
					try:
						#Admin
						success, new_pass = change_my_password(logged_user,logged_user_pass,privilege_granted)
					except Exception as e:
						print("Exception generated: ", e)
				
				if success:
					logged_user_pass = new_pass
		elif option == "4":
			login = False
			privilege_granted = False
			logged_user = ""
			logged_user_pass = ""
			print("Logout sucessfull!")
		elif option == "5":
			delete_user()
		elif option == "6":
			make_user_admin()
		
		option="-1"
	
