#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <elf.h>

/**
 * This program will take in a binary and overwrite the sections table with
 * zeroes. It will also overwite the sections names with zeroes. Finally, it
 * fixes up the ELF header and overwrites the old binary.
 */

/**
 * Finds the offset to the sections table.
 *
 * \param[in] p_data the ELF binary
 * \param[in,out] p_sec_count the number of sections in the section table
 * \param[in,out] p_str_index the section index of the section strings table
 * \return a pointer to the start of the sections table
 */
Elf64_Shdr* find_sections(std::string& p_data, int& p_sec_count, int& p_str_index)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' ||
        p_data[3] != 'F')
    {
        return NULL;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);

    Elf64_Off section_offset = ehdr->e_shoff;
    ehdr->e_shoff = 0;

    p_sec_count = ehdr->e_shnum;
    ehdr->e_shnum = 0;

    p_str_index = ehdr->e_shstrndx;
    ehdr->e_shstrndx = 0;

    return reinterpret_cast<Elf64_Shdr*>(&p_data[section_offset]);
}

/**
 * Overwrites all the section headers with zeros and zeroes out the strings
 *
 * \param[in] p_data the ELF binary
 * \param[in] p_sections a pointer to the first entry in the sections table
 * \param[in] p_sec_count the number of entries in the sections table
 * \param[in] p_str_index the index of the table we are going to remove
 * \return true if we successfully overwrote everything
 */
bool remove_headers(std::string& p_data, Elf64_Shdr* p_sections, int p_sec_count,
                    int p_str_index)
{
    // look through all the headers. Ensure nothing is using the string table
    // we plan on removing.
    Elf64_Shdr* iter = p_sections;
    for (int i = 0; i < p_sec_count; ++i, ++iter)
    {
        if (iter->sh_link == static_cast<Elf64_Word>(p_str_index))
        {
            std::cerr << "A section is still linked to the str index: " << iter->sh_link << std::endl;
            return false;
        }

        if (i == p_str_index)
        {
            // overwrite the strings
            memset(&p_data[iter->sh_offset], 0, iter->sh_size);
        }
    }

    // overwrite the entire table
    memset(p_sections, 0, p_sec_count * sizeof(Elf64_Shdr));
    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./stripBinary <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to ropen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    int section_count = 0;
    int str_index = 0;
    Elf64_Shdr* sections = find_sections(input, section_count, str_index);
    if (sections == NULL || reinterpret_cast<char*>(sections) > (input.data() + input.length()))
    {
        std::cerr << "Failed to find the sections table" << std::endl;
        return EXIT_FAILURE;
    }

    if (!remove_headers(input, sections, section_count, str_index))
    {
        return EXIT_FAILURE;
    }

    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cerr << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();
    return EXIT_SUCCESS;
}
