' win-capture-hidden.vbs -- start the capture with NO console window at all.
'
' Why this exists: the scheduled task ran powershell.exe directly with
' -WindowStyle Hidden, but powershell.exe CREATES its console and only then hides
' it. That moment is enough to take foreground, and an exclusive-fullscreen game
' loses its mode and drops the player to the desktop -- every two hours.
'
' wscript.exe has no console of its own, and WshShell.Run with intWindowStyle 0
' starts PowerShell hidden from the outset, so nothing is ever shown or focused.
' bWaitOnReturn is True on purpose: the task then stays Running for the real
' duration and its Last Result reflects the capture, instead of reporting success
' the instant it detaches.
'
' Arguments are passed straight through to win-capture-scheduled.ps1.
Option Explicit
Dim shell, i, arg, extra, scriptDir, ps1, rc
Set shell = CreateObject("WScript.Shell")
scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
ps1 = scriptDir & "win-capture-scheduled.ps1"
extra = ""
For i = 0 To WScript.Arguments.Count - 1
  arg = WScript.Arguments(i)
  If InStr(arg, " ") > 0 Then arg = Chr(34) & arg & Chr(34)
  extra = extra & " " & arg
Next
rc = shell.Run("powershell.exe -NoProfile -ExecutionPolicy Bypass -File " & _
               Chr(34) & ps1 & Chr(34) & extra, 0, True)
WScript.Quit rc
