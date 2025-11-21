
import subprocess
import os
import time

def run_thena_script(inputs):
    """Runs the Thena script with the given inputs."""
    with open("test_input.txt", "w") as f:
        for i in inputs:
            f.write(i + "\n")

    with open("test_input.txt", "r") as f:
        start_time = time.time()
        process = subprocess.Popen(
            ["python3", "Thena_dev_v19.py"],
            stdin=f,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        end_time = time.time()

    return stdout, stderr, end_time - start_time

def test_logging_in_interactive_mode():
    """Tests that logging is hidden in interactive mode."""
    # Create a dummy file to encrypt
    with open("test_file.txt", "w") as f:
        f.write("This is a test file.")

    # Run the script with inputs to encrypt the file
    inputs = [
        "1",  # Encrypt
        "test_file.txt",
        "password123",
        "n",  # No keyfile
        "n",  # Don't delete original
        "3"   # Exit
    ]
    stdout, stderr, duration = run_thena_script(inputs)

    # Check that there is no logging output in stdout
    assert "INFO" not in stdout
    assert "DEBUG" not in stdout

    # Clean up created files
    os.remove("test_file.txt")
    os.remove("test_input.txt")
    # The encrypted file is created with a timestamp, so we need to find it to delete it
    for file in os.listdir("."):
        if file.endswith(".encrypted"):
            os.remove(file)

if __name__ == "__main__":
    test_logging_in_interactive_mode()
    print("Test passed!")
