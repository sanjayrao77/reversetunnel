/*
 * blockmem.c - save mallocs by suballocating blocks
 * Copyright (C) 2021 Sanjay Rao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "conventions.h"

#include "blockmem.h"

CLEARFUNC(blockmem);

void deinit_blockmem(struct blockmem *blockmem) {
// don't mix init_/deinit_ and new_/free_ versions!!
struct node_blockmem *cur;
iffree(blockmem->node.data);
cur=blockmem->node.next;
while (cur) {
	struct node_blockmem *next;
	next=cur->next;
	free(cur);
#ifdef MALLOCPRINT
	fprintf(stderr,"%s:%d:%s free %p\n",__FILE__,__LINE__,__FUNCTION__,cur);
#endif
	cur=next;
}
}

int init_blockmem(struct blockmem *blockmem, unsigned int size) {
if (!size) size=DEFAULTSIZE_BLOCKMEM;
blockmem->current=&blockmem->node;
if (!(blockmem->node.data=malloc(size))) GOTOERROR;
#ifdef MALLOCPRINT
fprintf(stderr,"%s:%d:%s malloc %u %p\n",__FILE__,__LINE__,__FUNCTION__,size,blockmem->node.data);
#endif
blockmem->node.max=size;
blockmem->defsize=size-sizeof(struct node_blockmem);
return 0;
error:
	return -1;
}

void voidinit_blockmem(struct blockmem *blockmem, unsigned int size) {
if (!size) size=DEFAULTSIZE_BLOCKMEM;
blockmem->current=&blockmem->node;
blockmem->defsize=size;
}

void reset_blockmem(struct blockmem *blockmem) {
struct node_blockmem *node;
node=&blockmem->node;
blockmem->current=node;
while (1) {
	node->num=0;
	node=node->next;
	if (!node) break;
}
}

static struct node_blockmem *new_node_blockmem(unsigned int size) {
struct node_blockmem *node;
node=malloc(sizeof(struct node_blockmem)+size);
if (!node) return NULL;
#ifdef MALLOCPRINT
fprintf(stderr,"%s:%d:%s malloc %u %p\n",__FILE__,__LINE__,__FUNCTION__,sizeof(struct node_blockmem)+size,node);
#endif
node->data=(unsigned char *)node+sizeof(struct node_blockmem);
node->num=0;
node->max=size;
node->next=NULL;
return node;
}

int addnode_blockmem(struct node_blockmem *node, unsigned int size) {
if (!size) size=DEFAULTSIZE_BLOCKMEM;
if (!(node->next=new_node_blockmem(size))) GOTOERROR;
return 0;
error:
	return -1;
}

void *alloc_blockmem(struct blockmem *blockmem, unsigned int size) {
/* alloc returns a block of contiguous memory */
struct node_blockmem *node;
void *toret;
node=blockmem->current;
#ifdef MALLOCPRINT
// fprintf(stderr,"%s:%d:%s size:%u node->num:%u node->max:%u\n",__FILE__,__LINE__,__FUNCTION__,size,node->num,node->max);
#endif
while (1) {
	if (node->num+size<=node->max) {
		toret=(void *)node->data+node->num;
		node->num+=size;
		break;
	} else if (node->next) {
		node=node->next;
		blockmem->current=node;
	} else {
		{
			unsigned int ui;
			ui=size;
			if (ui<blockmem->defsize) ui=blockmem->defsize;
			node->next=new_node_blockmem(ui);
		}
		if (!node->next) GOTOERROR;
		node=node->next;
		blockmem->current=node;
	}
}
return toret;
error:
	return NULL;
}

unsigned char *memdup_blockmem(struct blockmem *blockmem, unsigned char *data, unsigned int datalen) {
unsigned char *ret;
if (!(ret=alloc_blockmem(blockmem,datalen))) GOTOERROR;
memcpy(ret,data,datalen);
return ret;
error:
	return NULL;
}

unsigned char *memdupz_blockmem(struct blockmem *blockmem, unsigned char *data, unsigned int datalen) {
unsigned char *ret;
if (!(ret=alloc_blockmem(blockmem,datalen+1))) GOTOERROR;
memcpy(ret,data,datalen);
ret[datalen]=0;
return ret;
error:
	return NULL;
}

char *strdup2_blockmem(struct blockmem *blockmem, unsigned char *str, unsigned int len) {
char *ret;
if (!(ret=alloc_blockmem(blockmem,len+1))) GOTOERROR;
memcpy(ret,str,len);
ret[len]='\0';
return ret;
error:
	return NULL;
}

unsigned int sizeof_blockmem(struct blockmem *blockmem) {
struct node_blockmem *node;
unsigned int count=0;
node=&blockmem->node;
while (1) {
	count+=node->num;
	node=node->next;
	if (!node) break;
}
return count;
}

struct blockmem *new_blockmem(unsigned int size) {
struct blockmem *b=NULL;
if (!(b=malloc(sizeof(struct blockmem)))) GOTOERROR;
#ifdef MALLOCPRINT
fprintf(stderr,"%s:%d:%s malloc %u %p\n",__FILE__,__LINE__,__FUNCTION__,sizeof(struct blockmem),b);
#endif
clear_blockmem(b);
if (init_blockmem(b,size)) GOTOERROR;
return b;
error:
	iffree(b);
	return NULL;
}
