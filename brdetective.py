import os
import sys
import hashlib
import sqlite3
import win32api
import subprocess
from glob import glob
from concurrent.futures import ThreadPoolExecutor, as_completed


def getFiles(path):
    contents = glob(f"{path}**", recursive=True)
    contents = [f for f in contents if os.path.isfile(f) and not f.endswith("brguard.db")]

    for file in contents:
        yield file


def calculateMD5(filepath):
    with open(filepath, "rb") as f:
        file_hash = hashlib.md5()

        while chunk := f.read(8192):
            file_hash.update(chunk)

        return(file_hash.hexdigest())


def createDB(dbLocation):
    connection = sqlite3.connect(dbLocation)
    cursor = connection.cursor()
    create_table = "CREATE TABLE FileHashes (Filepath text, MD5Sum, Modiftime text, Refreshed boolean, PRIMARY KEY(Filepath))"
    cursor.execute(create_table)
    connection.commit()
    connection.close()
    subprocess.check_call(["attrib", "+H", dbLocation])


def cleanOld(dbLocation):
    connection = sqlite3.connect(dbLocation)
    cursor = connection.cursor()
    deleteOld = "DELETE FROM FileHashes WHERE Refreshed = False"
    cursor.execute(deleteOld)
    connection.commit()
    connection.close()


def setAllOld(dbLocation):
    connection = sqlite3.connect(dbLocation)
    cursor = connection.cursor()
    cursor.execute("UPDATE FileHashes SET Refreshed = False")
    connection.commit()
    connection.close()


def processFile(file):
    md5 = calculateMD5(file)
    mtime = str(int(os.path.getmtime(file)))
    return file, md5, mtime


def processExisting(dbLocation, file):
    connection = sqlite3.connect(dbLocation)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM FileHashes WHERE Filepath=?", (file,))
    rowFound = cursor.fetchone()
    newfile, newmd5, newtime = processFile(file)

    if not rowFound:
        cursor.execute("INSERT INTO FileHashes VALUES (?, ?, ?, ?)", (newfile, newmd5, newtime, True))

    else:
        oldmd5, oldtime = rowFound[1], rowFound[2]

        if oldmd5 != newmd5 and oldtime == newtime:
            return file

        else:
            cursor.execute("UPDATE FileHashes SET MD5Sum = ?, Modiftime = ?, Refreshed = ? WHERE Filepath = ?", (newmd5, newtime, True, newfile))

    connection.commit()
    connection.close()


def main():
    with open(os.path.join(sys.path[0], "rules.config")) as conffile:
        for rule in conffile:

            dir = rule.strip()
            dbLocation = f"{dir}brguard.db"
            contents = getFiles(dir)
            results = []

            if os.path.exists(dbLocation):
                setAllOld(dbLocation)

                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [executor.submit(processExisting, dbLocation, file) for file in contents]

                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            results.append(result)

                if results:
                    with open(os.path.join(sys.path[0], "errors.log"), "a") as errorfile:
                        for line in results:
                            errorfile.write(f"{line}\n")

                    errors = "\n".join(results)
                    win32api.MessageBox(None, f"Bitrot Guard identified errors on the following files:\n\n{errors}")

                cleanOld(dbLocation)

            else:
                createDB(dbLocation)

                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [executor.submit(processFile, file) for file in contents]

                    for future in as_completed(futures):
                        results = future.result()

                        connection = sqlite3.connect(dbLocation)
                        cursor = connection.cursor()

                        try:
                            cursor.execute("INSERT INTO FileHashes VALUES (?, ?, ?, ?)", (results[0], results[1], results[2], True))

                        except sqlite3.IntegrityError as integrityError:
                            print(integrityError)

                        connection.commit()
                        connection.close()


if __name__ == "__main__":
    main()
