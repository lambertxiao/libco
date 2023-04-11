/*
* Tencent is pleased to support the open source community by making Libco available.

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

#ifndef __CO_CTX_H__
#define __CO_CTX_H__
#include <stdlib.h>

// 这是一个函数指针类型的定义。coctx_pfn_t是函数指针类型的名称，它指向一个具有两个void类型参数和返回值为void*类型的函数。
// 该函数指针类型通常用于协程上下文切换时保存和恢复协程的状态。函数指针可以指向不同的函数，以实现不同的协程调度策略。
typedef void* (*coctx_pfn_t)( void* s, void* s2 );
struct coctx_param_t
{
	const void *s1;
	const void *s2;
};

// 协程上下文的结构体定义，用于保存和恢复协程的状态
// 该结构体包含一个寄存器指针数组，用于存储协程最后一次挂起时CPU寄存器的值。数组中寄存器的数量取决于程序运行的CPU体系结构。
// ss_size字段指定堆栈的大小（以字节为单位），而ss_sp字段是指向堆栈开始处的指针。
struct coctx_t
{
#if defined(__i386__)
	void *regs[ 8 ];
#else
	void *regs[ 14 ];
#endif
	size_t ss_size;
	char *ss_sp;
	
};

int coctx_init( coctx_t *ctx );
int coctx_make( coctx_t *ctx,coctx_pfn_t pfn,const void *s,const void *s1 );
#endif
