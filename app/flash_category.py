def get_flash_category(css_class, heading):
    return { 'css_class': css_class, 'heading': heading }


class FlashCategory:
    SUCCESS = get_flash_category('alert-success', '')
    INFO = get_flash_category('alert-info', '')
    WARNING = get_flash_category('alert-warning', '')
    DANGER = get_flash_category('alert-danger', '')
