#ifndef _LIB_LIST_H
#define _LIB_LIST_H

#include <stddef.h>

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type,member));	\
})

struct list_node {
	struct list_node	*next;
	struct list_node	*prev;
};

struct list_head {
	struct list_node	node;
};

/* '**prev' points '*first' or '*next' of previous node */
struct hlist_node {
	struct hlist_node	*next;
	struct hlist_node	**prev;
};

struct hlist_head {
	struct hlist_node	*first;
};

static inline void list_add(struct list_node *new,
	struct list_node *next, struct list_node *prev)
{
	new->next = next;
	new->prev = prev;
	prev->next = new;
	next->prev = new;
	return;
}

static inline void list_add_before(struct list_node *node,
	struct list_node *new)
{
	list_add(new, node, node->prev);
	return;
}

static inline void list_add_after(struct list_node *node,
	struct list_node *new)
{
	list_add(new, node->next, node);
	return;
}

static inline void list_add_first(struct list_head *head,
	struct list_node *new)
{
	list_add_after(&head->node, new);
}

static inline void list_add_last(struct list_head *head,
	struct list_node *new)
{
	list_add_before(&head->node, new);
}

static inline void list_del(struct list_node *node)
{
	struct list_node *next = node->next;
	struct list_node *prev = node->prev;
	prev->next = next;
	next->prev = prev;
	return;
}

static inline void list_del_first(struct list_head *head)
{
	struct list_node *next = head->node.next;
	if(next != &(head->node))
		list_del(next);
	return;
}

static inline void list_del_last(struct list_head *head)
{
	struct list_node *prev = head->node.prev;
	if(prev != &(head->node))
		list_del(prev);
	return;
}

static inline void list_init(struct list_head *head)
{
	head->node.next = &head->node;
	head->node.prev = &head->node;
	return;
}

#define LIST_HEAD_INIT(name) { { &(name).node, &(name).node } }
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define list_empty(head)						\
	((head)->node.next == &((head)->node))

#define list_entry(ptr, type, member)					\
	container_of(ptr, type, member)

#define list_entry_safe(head, ptr, type, member) ({			\
	typeof(ptr) p = (ptr);						\
	(p != &((head)->node)) ? list_entry(p, type, member) : NULL;	\
})

#define list_first_entry(head, type, member)				\
	list_entry_safe(head, (head)->node.next, type, member)

#define list_for_each(head, data, member)				\
	list_for_each_dir(head, data, member, next)

#define list_for_each_rev(head, data, member)				\
	list_for_each_dir(head, data, member, prev)

#define list_for_each_dir(head, data, member, dir)			\
	for(	(data) = list_entry((head)->node.dir,			\
			typeof(*(data)),member);			\
		&((data)->member) != &((head)->node);			\
		(data) = list_entry((data)->member.dir,			\
			typeof(*(data)), member))

#define list_for_each_safe(head, data, member, temp)			\
	list_for_each_safe_dir(head, data, member, temp, next)

#define list_for_each_safe_rev(head, data, member, temp)		\
	list_for_each_safe_dir(head, data, member, temp, prev)

#define list_for_each_safe_dir(head, data, member, temp, dir)		\
	for(	(data) = list_entry((head)->node.dir,			\
			typeof(*(data)), member),			\
		(temp) = list_entry((data)->member.dir,			\
			typeof(*(data)),member);			\
		&((data)->member) != &((head)->node);			\
		(data) = (temp),					\
		(temp) = list_entry((data)->member.dir,			\
			typeof(*(data)), member))

static inline void hlist_add(struct hlist_node *new,
	struct hlist_node *next, struct hlist_node **prev)
{
	new->next = next;
	new->prev = prev;
	*prev = new;
	if(next)
		next->prev = &new->next;
	return;
}

static inline void hlist_add_before(struct hlist_node *node,
	struct hlist_node *new)
{
	hlist_add(new, node, node->prev);
	return;
}

static inline void hlist_add_after(struct hlist_node *node,
	struct hlist_node *new)
{
	hlist_add(new, node->next, &node->next);
	return;
}

static inline void hlist_add_first(struct hlist_head *head,
	struct hlist_node *new)
{
	hlist_add(new, head->first, &head->first);
	return;
}

static inline void hlist_del(struct hlist_node *node)
{
	struct hlist_node *next = node->next;
	struct hlist_node **prev = node->prev;
	*prev = next;
	if(next)
		next->prev = prev;
	return;
}

static inline void hlist_del_first(struct hlist_head *head)
{
	struct hlist_node *first = head->first;
	if(first)
		hlist_del(first);
	return;
}

static inline void hlist_init(struct hlist_head *head)
{
	head->first = NULL;
	return;
}

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) \
	struct hlist_head name = HLIST_HEAD_INIT

#define hlist_empty(head)						\
	(!(head)->first)

#define hlist_entry(ptr, type, member)					\
	container_of(ptr, type, member)

#define hlist_entry_safe(ptr, type, member) ({				\
	typeof(ptr) p = (ptr);						\
	p ? hlist_entry(p, type, member) : NULL;			\
})

#define hlist_first_entry(head, type, member)				\
	hlist_entry_safe((head)->first, type, member)

#define hlist_for_each(head, data, member)				\
	for(	(data) = hlist_entry_safe((head)->first,		\
			typeof(*(data)), member);			\
		(data);							\
		(data) = hlist_entry_safe((data)->member.next,		\
			typeof(*(data)), member))

#define hlist_for_each_safe(head, data, member, temp)			\
	for(	(data) = hlist_entry_safe((head)->first,		\
			typeof(*(data)), member),			\
		(data)							\
		&& ((temp) = hlist_entry_safe((data)->member.next,	\
			typeof(*(data)), member));			\
		(data);							\
		(data) = (temp),					\
		(data)							\
		&& ((temp) = hlist_entry_safe((data)->member.next,	\
			typeof(*(data)), member)))

#endif /* _LIB_LIST_H */
