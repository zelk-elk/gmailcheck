import argparse
import requests
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

def check(email, verbose='no'):
    url = "https://mail.google.com/mail/gxlu?email={0}".format(email)
    r = requests.get(url)

    try:
        if r.headers['set-cookie'] != '':
            if verbose == 'yes':
                print(r.headers)
            return email
    except:
        if verbose == 'yes':
            print(r.headers)
        return

def write_to_file(hnd, data):
    for d in data:
        if d is not None:
            hnd.write(str(d + "\n"))

def write_to_results(data):
    for d in data:
        if d is not None:
            print(f"{d} address valid")
        else:
            print("Invalid address")

def process_file(filename, verbose, output_file):
    pool = ThreadPool(20)  
    with open(filename) as fp:
        emails = [line.strip() for line in fp]
    results = pool.map(partial(check, verbose=verbose), emails)
    if output_file:
        with open(output_file, "w") as out_file:
            write_to_file(out_file, results)
    else:
        write_to_results(results)

def main():
    parser = argparse.ArgumentParser(description="Gmail Checker CLI")
    parser.add_argument("filename", help="Name of file with a list of emails")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-o", "--out", help="Name of output file")

    args = parser.parse_args()

    process_file(args.filename, "yes" if args.verbose else "no", args.out)

if __name__ == "__main__":
    main()
