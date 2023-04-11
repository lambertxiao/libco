/*
* Tencent is pleased to support the open source community by making Libco
available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "coctx.h"
#include <stdio.h>
#include <string.h>

#define ESP 0
#define EIP 1
#define EAX 2
#define ECX 3
// -----------
#define RSP 0
#define RIP 1
#define RBX 2
#define RDI 3
#define RSI 4

#define RBP 5
#define R12 6
#define R13 7
#define R14 8
#define R15 9
#define RDX 10
#define RCX 11
#define R8 12
#define R9 13

//----- --------
// 32 bit
// | regs[0]: ret |
// | regs[1]: ebx |
// | regs[2]: ecx |
// | regs[3]: edx |
// | regs[4]: edi |
// | regs[5]: esi |
// | regs[6]: ebp |
// | regs[7]: eax |  = esp
enum {
  // 用于存储下一条指令的地址
  kEIP = 0,
  // EBP寄存器用于存储函数堆栈帧的基地址
  kEBP = 6,
  // ESP寄存器用于存储当前栈指针，即栈顶地址
  kESP = 7,
};

//-------------
// 64 bit
// low | regs[0]: r15 |
//    | regs[1]: r14 |
//    | regs[2]: r13 |
//    | regs[3]: r12 |
//    | regs[4]: r9  |
//    | regs[5]: r8  |
//    | regs[6]: rbp |
//    | regs[7]: rdi |
//    | regs[8]: rsi |
//    | regs[9]: ret |  //ret func addr
//    | regs[10]: rdx |
//    | regs[11]: rcx |
//    | regs[12]: rbx |
// hig | regs[13]: rsp |
enum {
  // RDI寄存器用于存储函数的第一个参数
  kRDI = 7,
  // RSI寄存器用于存储函数的第二个参数
  kRSI = 8,
  // RET寄存器用于存储函数的返回地址
  kRETAddr = 9,
  // RSP寄存器用于存储当前栈指针，即栈顶地址
  kRSP = 13,
};

// 64 bit
// 用C的
extern "C" {
// 这是一个函数声明，使用了asm指令将函数名coctx_swap映射到汇编代码的符号coctx_swap中。
// 该函数接受两个coctx_t类型的指针参数，并在这两个上下文之间进行切换，以实现协程的切换。
// 具体来说，该函数将当前的上下文保存在第一个参数中，然后将第二个参数中的上下文恢复，并开始执行第二个上下文中指定的代码。
// 该函数通常用于实现协程调度器中的协程切换功能。
// asm是GCC和部分其他编译器提供的一个关键字，用于在C/C++代码中嵌入汇编代码。
extern void coctx_swap(coctx_t*, coctx_t*) asm("coctx_swap");
};
#if defined(__i386__)
int coctx_init(coctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

// 计算协程上下文中coctx_param结构体的存储位置：首先将当前栈指针sp指向协程栈顶，
// 然后减小coctx_param结构体的大小，使得可以在该位置存储协程参数。
// 计算协程切换后调用函数的返回地址：为了在协程切换后，恢复执行并继续执行协程中的函数，需要保存该函数的返回地址。
// 这里使用了一个trick：将协程参数的位置往后移动sizeof(void*)*2字节，然后在该位置的下一个void指针处存储函数地址。
// 设置协程参数：将参数值s、s1分别存储到coctx_param结构体的成员变量s1、s2中。
// 清空协程寄存器：使用memset()函数将协程寄存器数组regs中的值全部初始化为0。
// 设置协程栈指针：将协程栈指针regs[kESP]设置为当前栈指针sp减去2个void指针的大小，这样协程切换时可以正确恢复栈指针。
// 返回0：表示创建协程上下文成功。
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1) {
  // make room for coctx_param
  char* sp = ctx->ss_sp + ctx->ss_size - sizeof(coctx_param_t);
  sp = (char*)((unsigned long)sp & -16L);

  coctx_param_t* param = (coctx_param_t*)sp;
  void** ret_addr = (void**)(sp - sizeof(void*) * 2);
  *ret_addr = (void*)pfn;
  param->s1 = s;
  param->s2 = s1;

  memset(ctx->regs, 0, sizeof(ctx->regs));

  ctx->regs[kESP] = (char*)(sp) - sizeof(void*) * 2;
  return 0;
}
#elif defined(__x86_64__)
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1) {
  char* sp = ctx->ss_sp + ctx->ss_size - sizeof(void*);
  sp = (char*)((unsigned long)sp & -16LL);

  memset(ctx->regs, 0, sizeof(ctx->regs));
  void** ret_addr = (void**)(sp);
  *ret_addr = (void*)pfn;

  // 记住栈顶位置
  ctx->regs[kRSP] = sp;

  // 记住返回地址
  ctx->regs[kRETAddr] = (char*)pfn;

  // 记住第一个参数 
  ctx->regs[kRDI] = (char*)s;
  
  // 记住第二个参数
  ctx->regs[kRSI] = (char*)s1;
  return 0;
}

int coctx_init(coctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

#endif
