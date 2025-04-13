SECTIONS
{
    __romPos = 0;
    _gp = 0x0;
    tt_004_ROM_START = __romPos;
    tt_004_VRAM = ADDR(.tt_004);
    .tt_004 0x80170000 : AT(tt_004_ROM_START) SUBALIGN(4)
    {
        FILL(0x00000000);
        tt_004_DATA_START = .;
        sword_c = .;
        build/us/src/servant/tt_004/sword.c.o(.data);
        servant_common_c = .;
        build/us/src/servant/tt_004/servant_common.c.o(.data);
        sword_sprite_data_c = .;
        build/us/src/servant/tt_004/sword_sprite_data.c.o(.data);
        sword_data_c = .;
        build/us/src/servant/tt_004/sword_data.c.o(.data);
        servant_events_c = .;
        build/us/src/servant/tt_004/servant_events.c.o(.data);
        . = ALIGN(., 4);
        tt_004_DATA_END = .;
        tt_004_DATA_SIZE = ABSOLUTE(tt_004_DATA_END - tt_004_DATA_START);
        tt_004_RODATA_START = .;
        build/us/src/servant/tt_004/sword.c.o(.rodata);
        build/us/src/servant/tt_004/servant_common.c.o(.rodata);
        . = ALIGN(., 4);
        tt_004_RODATA_END = .;
        tt_004_RODATA_SIZE = ABSOLUTE(tt_004_RODATA_END - tt_004_RODATA_START);
        tt_004_TEXT_START = .;
        build/us/src/servant/tt_004/sword.c.o(.text);
        build/us/src/servant/tt_004/servant_common.c.o(.text);
        . = ALIGN(., 4);
        tt_004_TEXT_END = .;
        tt_004_TEXT_SIZE = ABSOLUTE(tt_004_TEXT_END - tt_004_TEXT_START);
        tt_004_BSS_START = .;
        build/us/src/servant/tt_004/sword.c.o(.bss);
        build/us/src/servant/tt_004/servant_common.c.o(.bss);
        . = ALIGN(., 4);
        tt_004_BSS_END = .;
        tt_004_BSS_SIZE = ABSOLUTE(tt_004_BSS_END - tt_004_BSS_START);
    }
    __romPos += SIZEOF(.tt_004);
    __romPos = ALIGN(__romPos, 4);
    . = ALIGN(., 4);
    tt_004_ROM_END = __romPos;
    tt_004_VRAM_END = .;

    /DISCARD/ :
    {
        *(*);
    }
}
