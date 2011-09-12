#ifndef LIST_H
#define LIST_H

/*
 * Define a linked list
 */
#define LIST_HEAD(name, type)                                               \
	struct name {                                                       \
		struct type	*l_first,                                   \
				*l_last;                                    \
	}
#define LIST_ENTRY(name, type)                                              \
	struct name {                                                       \
		struct type	*l_prev,                                    \
				*l_next;                                    \
	}

/*
 * Accessors
 */
#define LIST_FIRST(head)		((head)->l_first)
#define LIST_LAST(head)			((head)->l_last)
#define LIST_PREV(entry, field)		((entry)->field.l_prev)
#define LIST_NEXT(entry, field)		((entry)->field.l_next)

/*
 * Test a list for emptiness
 */
#define LIST_EMPTY(head)		(LIST_FIRST(head) == NULL)

/*
 * Iteration
 */
#define LIST_FOREACH(var, head, field)                                      \
	for ((var) = LIST_FIRST(head);                                      \
	     (var) != NULL;                                                 \
	     (var) = LIST_NEXT(var, field))
#define LIST_FOREACH_SAFE(var, head, field, tmp)                            \
	for ((var) = LIST_FIRST(head),                                      \
	      (tmp) = (var) != NULL? LIST_NEXT(var, field) : NULL;          \
	     (var) != NULL;                                                 \
	     (var) = (tmp),                                                 \
	      (tmp) = (var) != NULL? LIST_NEXT(var, field) : NULL)

/*
 * Insertion
 */
#define LIST_INSERT_FIRST(head, entry, field)                               \
	do {                                                                \
		if (LIST_FIRST(head) != NULL)                               \
			LIST_PREV(LIST_FIRST(head), field) = (entry);       \
		else                                                        \
			LIST_LAST(head) = (entry);                          \
		LIST_NEXT(entry, field) = LIST_FIRST(head);                 \
		LIST_FIRST(head) = (entry);                                 \
	} while (0)
#define LIST_INSERT_LAST(head, entry, field)                                \
	do {                                                                \
		if (LIST_LAST(head) != NULL)                                \
			LIST_NEXT(LIST_LAST(head), field) = (entry);        \
		else                                                        \
			LIST_FIRST(head) = (entry);                         \
		LIST_PREV(entry, field) = LIST_LAST(head);                  \
		LIST_LAST(head) = (entry);                                  \
	} while (0)
#define LIST_INSERT_BEFORE(head, pos, entry, field)                         \
	do {                                                                \
		LIST_PREV(entry, field) = LIST_PREV(pos, field);            \
		if (LIST_PREV(pos, field) == NULL)                          \
			LIST_FIRST(head) = (entry);                         \
		else                                                        \
			LIST_NEXT(LIST_PREV(pos, field), field) = (entry);  \
		LIST_NEXT(entry, field) = (pos);                            \
		LIST_PREV(pos, field) = (entry);                            \
	} while (0)
#define LIST_INSERT_AFTER(head, pos, entry, field)                          \
	do {                                                                \
		LIST_NEXT(entry, field) = LIST_NEXT(pos, field);            \
		if (LIST_NEXT(pos, field) == NULL)                          \
			LIST_LAST(head) = (entry);                          \
		else                                                        \
			LIST_PREV(LIST_NEXT(pos, field), field) = (entry);  \
		LIST_PREV(entry, field) = (pos);                            \
		LIST_NEXT(pos, field) = (entry);                            \
	} while (0)

/*
 * Removal
 */
#define LIST_REMOVE(head, entry, field)                                     \
	do {                                                                \
		if (LIST_PREV(entry, field) != NULL)                        \
			LIST_NEXT(LIST_PREV(entry, field), field) =         \
			    LIST_NEXT(entry, field);                        \
		else                                                        \
			LIST_FIRST(head) = LIST_NEXT(entry, field);         \
		if (LIST_NEXT(entry, field) != NULL)                        \
			LIST_PREV(LIST_NEXT(entry, field), field) =         \
			    LIST_PREV(entry, field);                        \
		else                                                        \
			LIST_LAST(head) = LIST_PREV(entry, field);          \
	} while (0)
#define LIST_REMOVE_FIRST(head, field)                                      \
	do {                                                                \
		LIST_FIRST(head) = LIST_NEXT(LIST_FIRST(head), field);      \
		if (LIST_FIRST(head) == NULL)                               \
			LIST_LAST(head) = NULL;                             \
		else                                                        \
			LIST_PREV(LIST_FIRST(head), field) = NULL;          \
	} while (0)
#define LIST_REMOVE_LAST(head, field)                                       \
	do {                                                                \
		LIST_LAST(head) = LIST_PREV(LIST_LAST(head), field);        \
		if (LIST_LAST(head) == NULL)                                \
			LIST_FIRST(head) = NULL;                            \
		else                                                        \
			LIST_NEXT(LIST_LAST(head), field) = NULL;           \
	} while (0)

#endif /* LIST_H */

/* end list.h */
