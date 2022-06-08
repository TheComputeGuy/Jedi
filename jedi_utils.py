from models.base_class import Commit
import time
import re


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
        c_out["tot_mal_pfiles"] = c_obj.tot_mal_pfiles
        op["plugin_info"][c_obj.commit_id] = c_out

    analysis_end = time.time()
    op["time"] = analysis_end - analysis_start
    # print("OP", op)
    return op
