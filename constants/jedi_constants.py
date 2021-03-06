plugin_header = ["Plugin Name:", "Plugin URI:", "Description:", "Version:", "Author:", "Author URI:", "Text Domain:", "Domain Path:", "Network:", "Site Wide Only:", "License:", "License URI:", "Theme Name:", "Theme URI:", "Template Name:"]
plugin_api = ["has_filter", "add_filter", "apply_filters", "apply_filters_ref_array", "current_filter", "remove_filter", "remove_all_filters", "doing_filter", "has_action", "add_action", "do_action", "do_action_ref_array", "did_action", "remove_action", "remove_all_actions", "doing_action", "register_activation_hook", "register_uninstall_hook", "register_deactivation_hook"]
plugin_ref = ["include", "require", "include_once", "require_once", "get_template_part"]
plugin_contenido_xpath = [".//plugin_name", ".//plugin_foldername", ".//uuid", ".//description", ".//author", ".//copyright", ".//mail", ".//website", ".//version"]
plugin_joomla_xpath = [".//name", ".//author", ".//creationDate", ".//copyright", ".//license", ".//authorEmail", ".//authorUrl", ".//version", ".//description", ".//isapplication", ".//isbrowseable"]
dr7_core_modules = ["Aggregator", "Block", "Blog", "Book", "Color", "Comment", "Contact", "Contextual links", "Dashboard", "Database logging", "Field", "Field UI", "File", "Filter", "Forum", "Help", "Image", "Locale", "Menu", "Node", "OpenID", "Overlay", "Path", "PHP filter", "Poll", "Profile", "RDF", "Search", "Shortcut", "Testing", "Statistics", "Syslog", "System", "Taxonomy", "Toolbar", "Tracker", "Content translation", "Trigger", "Update manager", "User"]
dr8_core_modules = ["Actions", "Aggregator", "Automated Cron", "Ban", "HTTP Basic Authentication", "BigPipe", "Block", "Custom Block", "Place Blocks", "Book", "Breakpoint", "CKEditor", "Color", "Comment", "Configuration Manager", "Configuration Translation", "Contact", "Content Moderation", "Content Translation", "Contextual links", "Datetime", "Datetime Range", "Database logging", "Internal Dynamic Page Cache", "Text Editor", "Entity Reference", "Field", "Field Layout", "Field UI", "File", "Filter", "Forum", "HAL", "Help", "Help Topics", "History", "Image", "Inline Form Errors", "JSON:API", "Language", "Layout Builder", "Layout Discovery", "Link", "Locale", "Media", "Media Library", "Custom Menu Links", "Menu UI", "Migrate", "Migrate Drupal", "Migrate Drupal Multilingual", "Migrate Drupal UI", "Node", "Options", "Internal Page Cache", "Path", "Path alias", "Quick Edit", "RDF", "Responsive Image", "RESTful Web Services" "Search", "Serialization", "Settings Tray", "Shortcut", "Testing", "Statistics", "Syslog", "System", "Taxonomy", "Telephone", "Text", "Toolbar", "Tour", "Tracker", "Update Manager", "User", "Views", "Views UI", "Workflows", "Workspaces"]
files_joomla_xpath = ".//files/filename"
func_before_regex = r"(?<![a-zA-Z0-9\_])"
func_after_regex = r"(?=(\s*(\/\*.*\*\/)*(\/\/.*\n+)*(\#.*\n+)*\())" # Catches intermittent php comments & newline between function name and open parentheses
ph_before_regex = r"(\n)[^\S\n]*(\/\*)?[^\S\n]*(\*)*[^\S\n]*"
ph_after_regex = r"[^\S\n]+"
version_regex = r"[^\S\n]*([0-9]+\.)+[0-9]+"
cutoff_score_percentage = 90
header_score = 3
api_score = 2
ref_score = 1
table_report = "table_report.csv"
files_keyword = "Plugin Files"
can_plugin_keyword = "Canonical Plugin Name"
num_plugin_keyword = "Number of Plugin Files"
plugin_keywords = ["Plugin Name", "X-Plugin Name", "Theme Name"]
plugin_keyword = "Plugin Name"
theme_keyword = "Theme Name"
wnum_keyword = "Website Count"
version_keyword = "Latest Version"
change_keyword = "Changes"
orphan_keyword = "Orphaned Plugins"
del_keyword = "Deleted"
path_keyword = "Plugin Path"
score_keyword = "Plugin Score"
api_keyword = "API"
ast_keyword = "AST"
ref_keyword = "Referenced Files"
em_keyword = "Extension Match"
jsons_regex_folder = "./JSONS_REGEX/"
jsons_ast_folder = "./JSONS_AST/"
block_size = 65536
db_name = "hashes.db"
table_name = "main_table"
hash_list = "hash"
listing = "listing" # blacklist is 0, greylist is 1, whitelist is 2
cms_scanner_cache = "cms_scanner.pickle"
wp_author = "Author"
wp_author_uri = "Author URI"
wp_version = "Version"
wp_plugin_uri = "Plugin URI"
wp_theme_uri = "Theme URI"
wp_license = "License"
wp_description = "Description"
jo_name = "name"
jo_author = "author"
jo_license = "license"
jo_authorEmail = "authorEmail"
jo_authorUrl = "authorUrl"
jo_version = "version"
jo_description = "description"
dr_name = "name"
dr_description = "description"
dr_version = "version"
dr_files = "files"
