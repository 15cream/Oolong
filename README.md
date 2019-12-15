# Durarara
IDA plugin, analyzes Mach-O based on the decompiler output ctree.

## Pure.py
主要目标是获得Mach-O二进制的调用图CallGraph，CG。

其中的数据流分析是基于汇编代码实现。

这个分析器是idaTask.py的改版，后续应该会继续更新，目前尚不完善。

## idaTask.py
目标是获得Mach-O二进制的调用图CallGraph。仅针对ARM64的Mach-O二进制。

比较特殊的地方在于，它是基于ida decompiler实现的。这要求你的IDA首先能够对Mach-O二进制实现反编译，获得伪码。

当我们不对Mach-O进行反编译，仅仅执行反汇编时，通过IDA提供的接口获得的CG十分不完整，因为它没对Message进行解析。

如果你对整个Mach-O进行反编译，会有25%左右的Message被解析成功，IDA提供的CG中caller和message handler之间是有边的。

但25%肯定也远远不够啊。分析其原因呢，1）有很大一部分Message的handler是动态链接的，最主要的就是 Framework methods；2）有一部分是没做好类型传递，导致无法正确识别变量的类型，进而也就影响了Message的解析；3）其他就是一些IDA没有care的细节，例如Dispatch，block，arc calls，这些会影响类型传递或者是控制流转移。

所以在idaTask.py中，我们就陆续处理这些问题，最终Message的解析率大概有83%吧。与PiOS的结果差不多，但性质上差很多，因为当时没有广泛使用Block。
也许还有提升的空间，但是暂时没有时间去处理了。

从代码可以看到，就是对ctree进行分析、修正的过程。

### 关于代码细节
Frame、 Path、SS_API、SS_API、NSUserdefaults、NSUserdefaults这些都可以不看，原本是用来做污点分析的。

tm = TaskManager()  # 完成初始化工作

tm.analyze_in_sequence() # 对Mach-O中的所有方法进行分析，结果存放在CG.sharedCG中，可以通过调用dump_result将其存档

具体的分析细节可以从上述两个调用入手查看实现（近期可能没法写更详细的文档了，过年可以试着整理一下并补一补）。
其中，在TaskManager的初始化工作中，有一句是Frameworks.build_from_dir(r'E:\0_share\experiments\IDA\analysis\headers')，该路径下存放的是iOS frameworks的所有头文件，我们对这些头文件进行文本分析获得framework中的Objective-C runtime metadata。这部分内容不是很准确，大家可以自行修改。

