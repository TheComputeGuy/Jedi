import sys
import time
import os
import re
import copy
import json
import gzip
import subprocess
import argparse
import git
import magic
from multiprocessing import Pool, cpu_count
from analysis_rules.analysis_downloader_plugin import Analysis_Downloader_Plugin
from analysis_rules.analysis_err_report import Analysis_Err_Report
from analysis_rules.analysis_fc_plugin import Analysis_FC_Plugin
from analysis_rules.analysis_obf_plugin import Analysis_Obf_Plugin
from analysis_rules.analysis_shell_detect import Analysis_Shell_Detect
from models.base_class import Website, FileMetadata
from constants.states import State
from jedi_utils import *

mal_plugin_analyses = [
    Analysis_Obf_Plugin(),         # Obfuscation
    Analysis_Shell_Detect(),       # Webshells in plugins
    Analysis_Err_Report(),         # Disable Error Reporting
    Analysis_FC_Plugin(),          # Function Construction
    Analysis_Downloader_Plugin(),  # Downloaders
]


def do_file_operations(file_obj):
    if file_obj.state not in [State.A.value, State.D.value, State.M.value, State.R.value, State.NC.value,
                              State.NC_D.value]:
        print("ERROR: New state found. State: ", file_obj.state, file_obj.filepath, file=sys.stderr)

    if file_obj.state == State.D.value:
        # Reset the suspicious tags when a file is deleted.
        # Check analysis_example.py to understand suspicious_tags.
        if file_obj.suspicious_tags:
            file_obj.suspicious_tags = []

    # Run analyses only if the file changed. We don't want to repeat
    # the analyses on unchanged files.
    if file_obj.state == State.A.value or file_obj.state == State.M.value or file_obj.state == State.R.value:
        if not os.path.isfile(file_obj.filepath):
            return file_obj

    return file_obj


def do_malicious_file_detection(file_obj):
    with open(file_obj.filepath, 'r', errors="ignore") as f:
        read_data = f.read()

    try:  # Generate AST for Analysis Passes
        cmd = [
            'php',
            '-f',
            './ast_utils/generateAST.php',
            file_obj.filepath
        ]

        file_obj.ast = subprocess.check_output(cmd)

    except Exception as e:
        print("ENCOUNTERED EXCEPTION {} FOR {}".format(e, file_obj.filepath), file=sys.stderr)

    for reanalysis in mal_plugin_analyses:
        reanalysis.reprocessFile(file_obj, read_data)

    file_obj.ast = None  # mem cleanup

    if file_obj.suspicious_tags:
        file_obj.is_malicious = True

    return file_obj


class Framework:

    def __init__(self, website_path=None) -> None:
        if website_path.endswith("/"):
            pass
        else:
            website_path = website_path + "/"
        self.website = Website(website_path)
        self.commits = []

    def get_file_list(self, commit_obj, init):
        exclude = ['.codeguard', '.git', '.gitattributes']
        file_list = []
        ma = magic.Magic(mime=True)

        # Parse through all the directories and get all files for the first commit or if the previous commit has zero files
        num_files = 0
        if commit_obj == self.commits[0] or init:
            for directory_path, subdirectories, filenames in os.walk(self.website.website_path, topdown=True):
                # Exclude files in .git and .codeguard directories
                subdirectories[:] = [directory for directory in subdirectories if directory not in exclude]
                filenames[:] = [file for file in filenames if file not in exclude]

                # If no files in this commit, then set commit_obj.initial to False so we get full filelist again in the next commit
                if filenames:
                    commit_obj.initial = True

                # For the first commit, the state is considered as file added(A)
                for file in filenames:
                    full_file_path = os.path.join(directory_path, file)
                    if os.path.islink(full_file_path):
                        mime = 'sym_link'
                    else:
                        try:
                            mime = ma.from_file(full_file_path.encode("utf-8", 'surrogateescape'))
                        except  Exception as e:
                            print("MIME_ERROR:", e, "Could no encode filename", full_file_path, file=sys.stderr)
                            mime = None
                        file_list.append(FileMetadata(full_file_path, file, State.A.value, mime))
            num_files = len(file_list)
        else:
            '''
            Second commit onwards, copy the file_list from the previous commit, 
            and only modify changed files. Add new files if any, and change the state
            of modified or renamed files.
            '''
            prev_index = self.commits.index(commit_obj) - 1
            file_list = copy.deepcopy(self.commits[prev_index]._file_list)

            # Free up memory
            self.commits[prev_index]._file_list = None

            found_index_list = []
            for diff in commit_obj.parent.diff(commit_obj.commit_obj):
                # Ignore all the changes in .codeguard directors
                if '.codeguard' not in diff.b_path:
                    '''
                    Side note:
                    diff.a_path -> path of the file in parent (older) commit object
                    diff.b_path -> path of the file in child (newer) commit object
                    If a file is renamed, the old name is considered 'deleted' in the new commit
                    '''
                    # Clean up git python string madness for non-ascii characters
                    if re.search(octals, diff.a_path):
                        diff_a_path = fix_git_trash_strings(diff.a_path)
                    else:
                        diff_a_path = diff.a_path
                    if re.search(octals, diff.b_path):
                        diff_b_path = fix_git_trash_strings(diff.b_path)
                    else:
                        diff_b_path = diff.b_path

                    # print("A_MODE", diff.a_mode, diff_a_path)
                    # print("B_MODE", diff.b_mode, diff_b_path)

                    # For renamed files, consider the original path as deleted
                    if diff.change_type == State.R.value:
                        search_path = self.website.website_path + '/' + diff_a_path
                        found_index = search_file_list(search_path, file_list)
                        if found_index is not None:
                            file_list[found_index].state = State.D.value

                    ''' 
                    Check if diff result is already in our file list. 
                    Yes => update 'state' No => Add new instance to file_list
                    '''
                    ''' 
                    *********************************************************
                    NOTE: WEBSITE_PATH should end in "/"
                    *********************************************************
                    '''
                    search_path = self.website.website_path + diff_b_path
                    found_index = search_file_list(search_path, file_list)

                    if (found_index is not None):
                        file_list[found_index].state = diff.change_type
                        found_index_list.append(found_index)
                        # If there is permission change, update fileMetadata object
                        if diff.a_mode != 0 and diff.b_mode != 0:
                            if diff.a_mode != diff.b_mode:
                                file_list[found_index].permission_change = True
                        # print('FOUND', diff.change_type, diff.b_path)
                    else:
                        # Index not found implies a new file is being added
                        f_name_only = search_path.split('/')[-1]
                        try:
                            mime_type = ma.from_file(search_path.encode("utf-8", 'surrogateescape'))
                        except OSError as e:
                            print("=> Handled" + str(e))
                            mime_type = None
                        file_list.append(FileMetadata(search_path, f_name_only, diff.change_type, mime_type))
                        found_index_list.append(len(file_list) - 1)

            # If a file wasn't modified, set its state = NC for no change
            num_del_files = 0
            for indx, file_obj in enumerate(file_list):
                if file_obj.state in [State.D.value, State.NC_D.value]:
                    num_del_files += 1
                if indx not in found_index_list:
                    if file_obj.state == State.D.value or file_obj.state == State.NC_D.value:
                        file_obj.state = State.NC_D.value  # Deleted in the previous commit and did not come back in this commit
                    else:
                        file_obj.state = State.NC.value
            num_files = len(file_list) - num_del_files

        return file_list, num_files

    def run(self):
        analysis_start = time.time()
        repo = git.Repo(self.website.website_path, odbt=git.db.GitDB)
        # print('***************************************************')
        # print('***************************************************')
        # print('Current Website:', self.website.website_path)
        # print('***************************************************')
        # print('***************************************************')

        # Create worker pool so the workers are alive for all commits
        worker_pool = Pool(cpu_count())

        if not repo.bare:
            # Get all commits
            self.commits = get_commit_list(repo)
            self.commits.reverse()  # Reversing to start with the oldest commit first

            # Initial commit -- use init if first commit has no files
            # Use init with getFileList if first commit has no files
            is_initial_commit = True

            for commit_obj in self.commits:
                try:
                    repo.git.checkout(commit_obj.commit_id)
                except git.GitCommandError as e:
                    # TODO - check the exact error name, possibly different
                    # If local change error, delete 'em and re run :)
                    if 'overwritten by checkout:' in str(e):
                        repo.git.reset('--hard')
                        repo.git.checkout(commit_obj.commit_id)
                print('---------------------------------------------------')
                print('Current Commit ID:', commit_obj.commit_id, repo.head.commit.authored_datetime)
                print('---------------------------------------------------')

                # Get all Files
                files, commit_obj.num_files = copy.deepcopy(self.get_file_list(commit_obj, is_initial_commit))
                # print("Number of files:", c_obj.num_files)

                # No point processing anything if the commit has no files
                if not files:
                    continue
                is_initial_commit = False

                # Do file operations on all files in a commit in parallel 
                file_ops_output = worker_pool.map(do_file_operations, files)

                # files will contain the list of updated file objects (f_obj)
                files = []
                if file_ops_output:
                    for index, outs in enumerate(file_ops_output):
                        files.append(outs)

                # Code snippet to test without parallel processing
                # for f_obj in files:
                #    self.do_file_operations(f_obj)

                # Update the list of files to the Commit object
                commit_index = self.commits.index(commit_obj)
                self.commits[commit_index]._file_list = copy.deepcopy(files)

                files_to_analyze = []
                for file_obj in files:
                    file_obj.extension = get_extension(file_obj.filename)
                    if (file_obj.state in [State.A.value, State.M.value, State.R.value]) and ('php' in file_obj.mime_type):
                        files_to_analyze.append(file_obj)

                commit_obj.num_files_analysed = len(files_to_analyze)

                mal_detect_output = worker_pool.map(do_malicious_file_detection, files_to_analyze)

                if os.path.exists('./fc_pass_tmp'):  # rm FC pass's tempfile
                    os.remove('./fc_pass_tmp')

                # Update the malicious file info on the commit object
                total_mal_files_count = 0
                mal_files = []
                for file_obj in mal_detect_output:
                    if (file_obj.state in [State.A.value, State.M.value, State.R.value, State.NC.value]) and (
                            'php' in file_obj.mime_type):
                        if file_obj.suspicious_tags:
                            total_mal_files_count += 1
                            mal_files.append(file_obj)
                    if file_obj.state in [State.D.value]:
                        file_obj.suspicious_tags = []

                # print("Total number of mal files", tot_mal_files, c_obj.commit_id)
                if total_mal_files_count:
                    commit_obj.tot_mal_pfiles = total_mal_files_count
                    commit_obj.mal_files = mal_files

                # This breaks after first commit. Use for debugging purposes
                # break

            # postProcessWebsite
            for analysis in mal_plugin_analyses:
                analysis.postProcessWebsite(self.commits, self.website)

            website_output = process_outputs(self.website, self.commits, analysis_start)

            op_path = "results/" + self.website.website_path.split('/')[-2] + ".json.gz"
            if not os.path.isdir('results'):  # mkdir results if not exists
                os.makedirs('results')

            with gzip.open(op_path, 'w') as f:
                f.write(json.dumps(website_output, default=str).encode('utf-8'))

        else:
            print('Could not load repository at {} :('.format(self.website.website_path), file=sys.stderr)

        worker_pool.close()
        worker_pool.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("website_path", help="The path of website to be analysed")
    args = parser.parse_args()

    website_path = args.website_path
    start = time.time()

    framework = Framework(website_path=website_path)
    framework.run()

    print("Time taken: ", time.time() - start)
