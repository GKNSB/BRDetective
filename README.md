## BRDetective
Simple python script that checks for files corrupted by bitrot.

1. Edit the config file with the directories you want monitored (e.x. `C:\Users\asdf\Desktop\`)
2. At first run, database files get generated in each location specified in the config with the checksums and last modified time of each file
3. At each next run, checks are performed against previous hashes
4. Stale database entries about old files are automatically deleted and new ones are added
5. If a file's checksum has been altered but the last modified time has not, an alert is poped on the screen and an error log is written
5. Run as a scheduled task
6. No arguments or anything