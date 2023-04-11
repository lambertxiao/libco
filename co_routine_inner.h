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


#ifndef __CO_ROUTINE_INNER_H__

#include "co_routine.h"
#include "coctx.h"
struct stCoRoutineEnv_t;
struct stCoSpec_t
{
	void *value;
};

// 保存协程的栈空间
struct stStackMem_t
{
  // 指向当前占用该栈内存的协程
	stCoRoutine_t* occupy_co;
  // 栈大小
	int stack_size;
  // 栈底部地址+栈大小
	char* stack_bp; //stack_buffer + stack_size
  // 起始地址，栈的底部
	char* stack_buffer;

};

struct stShareStack_t
{
	unsigned int alloc_idx;
	int stack_size;
	int count;
	stStackMem_t** stack_array;
};

struct stCoRoutine_t
{
  // 指向协程所在的协程环境的指针
	stCoRoutineEnv_t *env;
  // 指向协程执行的函数的指针
	pfn_co_routine_t pfn;
  // 传递给协程函数的参数
	void *arg;
  // 协程的上下文，包含寄存器等信息
	coctx_t ctx;
  // 标识协程是否已经开始执行
	char cStart;
  // 标识协程是否已经结束执行
	char cEnd;
  // 标识协程是否是主协程
	char cIsMain;
  // 标识系统调用钩子是否启用
	char cEnableSysHook;
  // 标识协程是否使用共享栈  
	char cIsShareStack;
  // 指向协程环境的私有数据
	void *pvEnv;

  // 指向协程的堆栈内存
	//char sRunStack[ 1024 * 128 ];
	stStackMem_t* stack_mem;


  // 栈顶指针
	//save satck buffer while confilct on same stack_buffer;
	char* stack_sp;
  // 保存堆栈数据的大小 
	unsigned int save_size;
  // 缓冲区, 在共享栈模式下，用来保存共享栈里的内容
	char* save_buffer;
  // 协程的私有数据
	stCoSpec_t aSpec[1024];
};



//1.env
void 				co_init_curr_thread_env();
stCoRoutineEnv_t *	co_get_curr_thread_env();

//2.coroutine
void    co_free( stCoRoutine_t * co );
void    co_yield_env(  stCoRoutineEnv_t *env );

//3.func



//-----------------------------------------------------------------------------------------------

struct stTimeout_t;
struct stTimeoutItem_t ;

stTimeout_t *AllocTimeout( int iSize );
void 	FreeTimeout( stTimeout_t *apTimeout );
int  	AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,uint64_t allNow );

struct stCoEpoll_t;
stCoEpoll_t * AllocEpoll();
void 		FreeEpoll( stCoEpoll_t *ctx );

stCoRoutine_t *		GetCurrThreadCo();
void 				SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev );

typedef void (*pfnCoRoutineFunc_t)();

#endif

#define __CO_ROUTINE_INNER_H__
