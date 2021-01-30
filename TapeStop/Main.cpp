#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#define __IDP__                 1
#define __NT__                  1
#define __X64__                 1

#pragma warning( push )  
#pragma warning( disable : 4267 )
#pragma warning( disable : 4244 )
#include "bytes.hpp"        // for bin_search2, parse_binpat_str, compiled_binpat_vec_t
#include <dbg.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <vector>
#pragma warning( pop ) 

#pragma comment(lib, "ida.lib")
#pragma comment(lib, "pro.lib")

using namespace std;

std::vector<ea_t> bpt_list = {};

// TODO: 
//		сохранение содержимого регистров в текстовик
//		сохранение содержимого стека в текстовик

struct ts_next_place_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t* ctx)
	{
		size_t count_bpt_list = bpt_list.size();
		msg("[TapeStop: quantity of pushfq %i]\n", count_bpt_list);
		msg("[TapeStop: pushfq address %a]\n", bpt_list[0]);

		// прыгнули внутрь вм
		run_to(bpt_list[0]);

		disable_bpt(bpt_list[0]);

		// поставим точку останова на .text секцию
		segment_t* textSeg = get_segm_by_name(".text");
		
		// проверим есть ли по данному адресу бряк
		// если нет, то поставим
		if (check_bpt(textSeg->start_ea) == BPTCK_NONE)
		{
			add_bpt(textSeg->start_ea);
		}
		// если бряк отключен - включим повторно
		else if (check_bpt(textSeg->start_ea) == BPTCK_NO) {
			enable_bpt(textSeg->start_ea);
		}

		// прыгнем в секцию .text (снаружи вм)
		continue_process();

		// удалим элемент из контейнера чтобы прыгнуть на след место
		bpt_list.erase(bpt_list.begin());

		return 0;
	}

	virtual action_state_t idaapi update(action_update_ctx_t* ctx)
	{
		return AST_ENABLE_ALWAYS;
	}
};

static ts_next_place_t ts_next_place;

action_desc_t action_NextOutsideVMPlace = ACTION_DESC_LITERAL(
	"TapeStop:NextOutsideVM",
	"Jump to the next place",
	&ts_next_place,
	"F3",
	"Jump to the following unprotected place outside of the virtual machine",
	65);

struct plugin_ctx_t : public plugmod_t
{
	virtual bool idaapi run(size_t) override;
};

bool idaapi plugin_ctx_t::run(size_t)
{
	bpt_list.clear();
	register_action(action_NextOutsideVMPlace);
	attach_action_to_menu("View/TapeStop/", action_NextOutsideVMPlace.name, SETMENU_APP);

	segment_t* relocSeg = get_segm_by_name(".reloc");
	segment_t* v_lizerSeg = get_segm_by_name(".v_lizer");

	// Адрес секции (ее начало и ее конец)
	ea_t start_ea = relocSeg->start_ea;
	ea_t end_ea = relocSeg->end_ea;

	// Найдем все инструкции
	compiled_binpat_vec_t binPat;
	parse_binpat_str(&binPat, 0x0, "9C", 16); // 9C - pushfq

	ea_t SearchStartAddr = start_ea;

	while (true)
	{
		SearchStartAddr = bin_search2(SearchStartAddr, end_ea, binPat, SEARCH_DOWN);
		if (SearchStartAddr == BADADDR)
		{
			break;
		}

		qstring mnem, tmp;
		print_insn_mnem(&tmp, SearchStartAddr);

		// TODO: мб не нужно вообще
		tag_remove(&mnem, tmp.c_str());

		// Отсортируем данные из контейнера, отсеяв лишние инструкции
		if (strcmp(mnem.c_str(), "pushfq") == 0) {
			bpt_list.push_back(SearchStartAddr);

			// Теперь у нас есть чистые адреса
			// На них нужно установить точки останова
			
			// проверим есть ли по данному адресу бряк
			// если нет, то поставим
			if (check_bpt(SearchStartAddr) == BPTCK_NONE) 
			{
				add_bpt(SearchStartAddr);
			}
			// если бряк отключен - включим повторно
			else if (check_bpt(SearchStartAddr) == BPTCK_NO) {
				enable_bpt(SearchStartAddr);
			} 
		}

		SearchStartAddr = SearchStartAddr + 3;
	}
	msg("[TapeStop: quantity of pushfq %i]\n", bpt_list.size());

	return true;
}

static plugmod_t* idaapi init(void)
{
	return new plugin_ctx_t;
}

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	"VM Explorer",
	"Plug-in for banal surfing in the virtual machine",
	"TapeStop",
	"F10"
};
