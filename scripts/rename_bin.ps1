# rename dqy Windows binary
$triple = rustc -vV | rg -o 'x.*'
Copy-Item .\target\release\dqy.exe .\target\release\dqy-${triple}.exe