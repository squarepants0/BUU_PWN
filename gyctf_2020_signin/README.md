# tcache中的类unsortedbin attack

题目内置后门需要在calloc之后是的全局变量ptr不为0即刻出发system

## 思路

填满tcahce后free一个chunk进入fastbin，利用UAF和edit改写该chunk的fd指针，使其指向全局变量ptr-0x10



## calloc

```c
void *
__libc_calloc (size_t n, size_t elem_size)
{
  mstate av;
  mchunkptr oldtop, p;
  INTERNAL_SIZE_T bytes, sz, csz, oldtopsize;
  void *mem;
  unsigned long clearsize;
  unsigned long nclears;
  INTERNAL_SIZE_T *d;

  /* size_t is unsigned so the behavior on overflow is defined.  */
  bytes = n * elem_size;
#define HALF_INTERNAL_SIZE_T \
  (((INTERNAL_SIZE_T) 1) << (8 * sizeof (INTERNAL_SIZE_T) / 2))
  if (__builtin_expect ((n | elem_size) >= HALF_INTERNAL_SIZE_T, 0))
    {
      if (elem_size != 0 && bytes / elem_size != n)
        {
          __set_errno (ENOMEM);
          return 0;
        }
    }

  void *(*hook) (size_t, const void *) =
    atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      sz = bytes;
      mem = (*hook)(sz, RETURN_ADDRESS (0));
      if (mem == 0)
        return 0;

      return memset (mem, 0, sz);
    }

  sz = bytes;

  MAYBE_INIT_TCACHE ();

  if (SINGLE_THREAD_P)
    av = &main_arena;
  else
    arena_get (av, sz);

  if (av)
    {
      /* Check if we hand out the top chunk, in which case there may be no
	 need to clear. */
#if MORECORE_CLEARS
      oldtop = top (av);
      oldtopsize = chunksize (top (av));
# if MORECORE_CLEARS < 2
      /* Only newly allocated memory is guaranteed to be cleared.  */
      if (av == &main_arena &&
	  oldtopsize < mp_.sbrk_base + av->max_system_mem - (char *) oldtop)
	oldtopsize = (mp_.sbrk_base + av->max_system_mem - (char *) oldtop);
# endif
      if (av != &main_arena)
	{
	  heap_info *heap = heap_for_ptr (oldtop);
	  if (oldtopsize < (char *) heap + heap->mprotect_size - (char *) oldtop)
	    oldtopsize = (char *) heap + heap->mprotect_size - (char *) oldtop;
	}
#endif
    }
  else
    {
      /* No usable arenas.  */
      oldtop = 0;
      oldtopsize = 0;
    }
  mem = _int_malloc (av, sz);  //<<<<< 
```

调用_int_malloc不会经过__libc_malloc，而对tcache的分配就是在\__libc_malloc进行的。所以calloc不会利用tcache