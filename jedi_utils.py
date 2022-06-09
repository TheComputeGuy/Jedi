from models.base_class import Commit
import time
import re
import constants.filetypes as filetype_dictionary


# Variables used to fix git mistakes in filenames that contain non-ascii characters
octals = re.compile('((?:\\\\\d\d\d)+)')
three_digits = re.compile('\d\d\d')


def fix_git_trash_strings(git_trash):
        ''' 
        Git diff.a_path and b_path replace non-ascii chacters by their
        octal values and replace it as characters in the string. This function 
        fixes this BS.
        '''
        git_trash = git_trash.lstrip('\"').rstrip('\"')
        match = re.split(octals, git_trash)
        pretty_strings = []
        for words in match:
            if re.match(octals, words):
                ints = [int(x, 8) for x in re.findall(three_digits, words)]
                pretty_strings.append(bytes(ints).decode())
            else:
                pretty_strings.append(words)
        return ''.join(pretty_strings)


def get_commit_list(repo):
    '''
    Get git commit objects and create a list of Commit objects for each
    commit
    '''
    commit_list = list(repo.iter_commits('master'))
    commits = []
    for c in commit_list:
        commits.append(Commit(c))
    return commits


def search_file_list(search_item, file_list):
    for file in file_list:
        if file.filepath == search_item:
            return file_list.index(file)
    return None


def get_extension(file_name):
    # Used Victor's hacky code from TARDIS to get the extension
        is_hidden = False
        if file_name[0] == '.':
            is_hidden = True

        file_types = file_name.split('.')
        possible_filetypes = []
        if len(file_types) > 1 and not is_hidden:
            for filetype in file_types:
                if filetype in filetype_dictionary.readable_to_ext:
                    possible_filetypes.append(filetype)
        elif len(file_types) > 2:
            for filetype in file_types:
                if filetype in filetype_dictionary.readable_to_ext:
                    possible_filetypes.append(filetype_dictionary.readable_to_ext[filetype])        
                    possible_filetypes.append(filetype)        
        if len(possible_filetypes) > 1:
            for pfg in possible_filetypes:
                if pfg != "svn-base":
                    file_extension = pfg
        elif len(possible_filetypes) == 1:
            file_extension = possible_filetypes[0]
            # Re-assigning type for some cases based on extn, only for ease of sorting outputs 
            if file_extension== 'ini':
                file_extension = 'php'
            elif file_extension == 'jsx':
                file_extension = 'js'
            elif (file_extension == 'json') or (file_extension == 'md'):
                file_extension = 'txt'
            elif (file_extension == 'woff') or (file_extension == 'ttf') or (file_extension == 'otf') or (file_extension == 'woff2') or (file_extension == 'eot'):
                file_extension = 'font'
        else:
            file_extension = None
        return file_extension


def process_outputs(website, commits, analysis_start):
    op = {}
    op["website_id"] = website.website_path.split('/')[-2]
    op["c_ids"] = []
    op["plugin_info"] = {}
    for c_obj in commits:
        # print('---------------------------------------------------')
        # print('Current Commit ID:', c_obj.commit_id, c_obj.date.strftime('%m/%d/%Y, %H:%M:$S')) 
        # print('---------------------------------------------------')
        op["c_ids"].append(c_obj.commit_id)
        c_out = {}
        c_out["date"] = c_obj.date.strftime('%m/%d/%Y, %H:%M:%S')
        c_out["num_files"] = c_obj.num_files
        # print("Number of files:", c_obj.num_files, len(c_obj._file_list))
        c_out["num_files_analysed"] = c_obj.num_files_analysed
        c_out["tot_mal_pfiles"] = c_obj.tot_mal_pfiles
        c_out["malicious_files"] = {}
        for mal_file in c_obj.mal_files:
            file_obj = {}
            file_obj["state"] = mal_file.state
            file_obj["mime_type"] = mal_file.mime_type
            file_obj["extension"] = mal_file.extension
            file_obj["suspicious_tags"] = mal_file.suspicious_tags
            file_obj["is_hidden_file"] = mal_file.hidden_file
            file_obj["in_hidden_dir"] = mal_file.in_hidden_dir
            c_out["malicious_files"][mal_file.filename] = file_obj
        op["plugin_info"][c_obj.commit_id] = c_out

    analysis_end = time.time()
    op["time"] = analysis_end - analysis_start
    # print("OP", op)
    return op
