import argparse as __xw__, os as __zt__, json as __rz__, re as __u__, statistics as __yt__, requests as __qh__
from pathlib import Path as __np__
from bs4 import BeautifulSoup as __kl__
from urllib.parse import urljoin as __jl__, urlparse as __ul__
import base64 as __a__, codecs as __b__

def __encode__(s):
    return __a__.b64encode(__b__.encode(s, 'rot_13')).decode()

def __decode__(s):
    return __b__.decode(__a__.b64decode(s).decode(), 'rot_13')

__banner__ = __encode__('''\n\
              ________    ____       __     ___________ ____  ______\n\
             / ____/ /_  / __ \_____/ /_   / ____/ ___// __ \/ ____/\n\
            / / __/ __ \/ / / / ___/ __/  / /    \__ \/ /_/ / /_    \n\
           / /_/ / / / / /_/ (__  ) /_   / /___ ___/ / _, _/ __/    \n\
           \____/_/ /_/\____/____/\__/   \____//____/_/ |_/_/       \n\
              ║║      By g h 0 s t _ r i 1 3 y       ║║\n\
    ''')

def __lx__():
    print(__decode__(__banner__))

def __oh__(__st__, __iu__=2, __zx__=None):
    if __zx__ is None:
        __zx__ = set()

    if __iu__ == 0 or __st__ in __zx__:
        return []

    __zx__.add(__st__)
    print(__decode__(__encode__("⟬⁕⟭ Crawling started...")))

    __tf__ = []
    __links__ = []

    try:
        __r__ = __qh__.get(__st__)
        __s__ = __kl__(__r__.text, 'html.parser')

        __fr__ = __s__.find_all(__decode__(__encode__('form')))
        for __form__ in __fr__:
            __action__ = __form__.get(__decode__(__encode__('action')))
            __method__ = __form__.get(__decode__(__encode__('method')), __decode__(__encode__('get'))).lower()
            __inputs__ = []
            for __input__ in __form__.find_all(__decode__(__encode__('input'))):
                __type__ = __input__.get(__decode__(__encode__('type')), __decode__(__encode__('text')))
                __name__ = __input__.get(__decode__(__encode__('name')))
                __value__ = __input__.get(__decode__(__encode__('value')), __decode__(__encode__('')))
                __inputs__.append({
                    __decode__(__encode__('type')): __type__,
                    __decode__(__encode__('name')): __name__,
                    __decode__(__encode__('value')): __value__,
                })
            __tf__.append({
                __decode__(__encode__('action')): __jl__(__st__, __action__),
                __decode__(__encode__('method')): __method__,
                __decode__(__encode__('inputs')): __inputs__,
            })

        for __link__ in __s__.find_all(__decode__(__encode__('a')), href=True):
            __hr__ = __link__[__decode__(__encode__('href'))]
            __parsed__ = __ul__(__hr__)
            if not __parsed__.netloc or __parsed__.netloc == __ul__(__st__).netloc:
                __full_url__ = __jl__(__st__, __hr__)
                if __full_url__ not in __zx__:
                    __links__.append(__full_url__)

        print(__decode__(__encode__("⟬✓⟭ Crawling finished.")))

    except Exception as __e__:
        print(__decode__(__encode__("⟬✕⟭ Failed to crawl")) + f" {__st__}: {__e__}")
        return __tf__

    for __lnk__ in __links__:
        __tf__ += __oh__(__lnk__, __iu__ - 1, __zx__)

    return __tf__

def __csrf__(__tf__):
    __vul__ = []

    for __f__ in __tf__:
        __csrf_token__ = False
        for __input__ in __f__[__decode__(__encode__('inputs'))]:
            if __input__[__decode__(__encode__('name'))] and __decode__(__encode__('csrf')) in __input__[__decode__(__encode__('name'))].lower():
                __csrf_token__ = True
                break
        if not __csrf_token__:
            __vul__.append(__f__)

    return __vul__

def __main__():
    __lx__()

    __prs__ = __xw__.ArgumentParser(description=__decode__(__encode__('CSRF Vulnerability Scanner')))
    __prs__.add_argument(__decode__(__encode__('-u')), __decode__(__encode__('--url')), help=__decode__(__encode__('Target URL')), required=True)
    __prs__.add_argument(__decode__(__encode__('--depth')), help=__decode__(__encode__('Crawling depth (default 2)')), default=2, type=int)
    __args__ = __prs__.parse_args()

    __target__ = __args__.url
    __depth__ = __args__.depth

    if not __target__.startswith((__decode__(__encode__('http://')), __decode__(__encode__('https://')))):
        print(__decode__(__encode__("⟬⁈⟭ Please provide a valid URL (starting with http:// or https://)")))
        return

    print(__decode__(__encode__("Crawling started")))
    __forms__ = __oh__(__target__, __iu__=__depth__)

    if not __forms__:
        print(__decode__(__encode__("⟬⁈⟭ No forms found.")))
        return

    print(__decode__(__encode__("Evaluating forms for CSRF vulnerabilities...")))
    __vulnerable__ = __csrf__(__forms__)

    if __vulnerable__:
        print(__decode__(__encode__("⟬✓⟭ CSRF vulnerability found in the following forms:")))
        for __form__ in __vulnerable__:
            print(__decode__(__encode__("⟬→⟭ Form with action:")) + f" {__form__[__decode__(__encode__('action'))]} " + __decode__(__encode__("and method:")) + f" {__form__[__decode__(__encode__('method'))]}")
    else:
        print(__decode__(__encode__("⟬✕⟭ No CSRF vulnerabilities found.")))

    print(__decode__(__encode__(" ⟬※⟭Scanning Completed "))

if __name__ == "__main__":
    __main__()
