' Pwn Notes auto sync - double click to start the hidden background watcher.
' It watches D:\ notes and publishes to GitHub Pages automatically.
Set sh = CreateObject("WScript.Shell")
py = "C:\Users\86139\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"
script = "C:\Users\86139\WorkBuddy\2026-11-11-09-33-36\hexo-pwn-notes\tools\watch_notes.py"
sh.Run """" & py & """ """ & script & """", 0, False
