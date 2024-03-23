import random
import string

# Define the file size in bytes (10MB)
# file_size = 10 * 1024 * 1024
file_size = 10 * 1024

# Generate random alphanumeric characters
alphanumeric_characters = string.ascii_letters + string.digits

# Generate the content for the file
file_content = ''.join(random.choice(alphanumeric_characters) for _ in range(file_size))

# Write the content to a file
with open('alphanumeric_file.txt', 'w') as file:
    file.write(file_content)

print("Alphanumeric file generated successfully.")

# Close the file
file.close()
