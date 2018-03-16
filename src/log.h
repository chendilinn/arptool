/*===============================================================
*   Copyright (C) 2017 All rights reserved.
*   
*   文件名称：function.h
*   创 建 者：陈迪林
*   创建日期：2018年03月16日 shanghai
*   描    述：
*
*   更新日志：
*
================================================================*/
#ifndef _LOG_H
#define _LOG_H

#define DEBUG
#ifdef DEBUG
	#define LOG(format, ...) \
	{ \
		printf("[LOG]\t%s\t%d\t" format, __FILE__, __LINE__, ##__VA_ARGS__); \
	}
#else
	#define LOG(format, ...)  
#endif

#endif
