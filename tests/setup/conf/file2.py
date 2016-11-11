variants = {
    'site': {
        'min_timedelta': '1 seconds',
        'exclude': ['*.log', '*.tar', '*.tar.gz', '*.zip', '*.sql', 'public_html/_tpl_cache_',
                    '*.jpeg', '*.jpg', '*.pdf', '*.gz', '*.sql', '*.zip', "public_html/.git",
                    "public_html/userfiles", "public_html/admin/crawler"
                    'public_html/_tpl_comp_'],
        'src': {'path': '/var/www/site/public_html/modules', 'host': 'user@site.com'},
        'dest': {'path': '/tmp/forwardspb.ru_modules', 'host': ''}
    }
}
