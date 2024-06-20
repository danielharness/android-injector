ENTRY(_start);

SECTIONS
{
    . = ALIGN(16);

    .text :
    {
        *(.text.prologue)
        *(.text)
        *(.text.*)
    }

    . = ALIGN(16);

    .data :
    {
        *(.rodata)
        *(.rodata.*)
        *(.data)
    }

    .debug :
    {
        *(.ARM.exidx)
    }
}
