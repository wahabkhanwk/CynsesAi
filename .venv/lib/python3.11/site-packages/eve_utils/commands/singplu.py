import inflect

def get_pair(word):
    p = inflect.engine()
    
    singular = word if p.singular_noun(word) == False else p.singular_noun(word)
    plural = word if p.singular_noun(word) else p.plural_noun(word)
    
    if singular == plural:  # in case of words like moose, fish
        plural = plural + 's'

    return (singular, plural)