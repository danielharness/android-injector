ENTRY(start);

SECTIONS
{
    . = ALIGN(16);

    .text :
    {
        *(.entry)
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
