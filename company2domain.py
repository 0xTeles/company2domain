import psycopg2
import sys
connection = {
    'host': 'crt.sh',
    'port': 5432,
    'database': 'certwatch',
    'user': 'guest',
    'password': None, 
    'sslmode': 'disable'
}

query = """
WITH ci AS (
    SELECT 
        min(sub.CERTIFICATE_ID) ID,
        array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
        x509_commonName(sub.CERTIFICATE) COMMON_NAME,
        x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
        x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
        encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER,
        count(sub.CERTIFICATE_ID)::bigint RESULT_COUNT
    FROM (
        SELECT cai.*
        FROM certificate_and_identities cai
        WHERE 
            plainto_tsquery('certwatch', '%s') @@ identities(cai.CERTIFICATE)
            AND plainto_tsquery('certwatch', '%s') @@ to_tsvector('certwatch', cai.NAME_VALUE)
            AND cai.NAME_TYPE = '2.5.4.10' -- organizationName
        LIMIT 10000
    ) sub
    GROUP BY sub.CERTIFICATE
)
SELECT 
    ci.COMMON_NAME,
    array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE
FROM ci
LEFT JOIN LATERAL (
    SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
    FROM ct_log_entry ctle
    WHERE ctle.CERTIFICATE_ID = ci.ID
) le ON TRUE
ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;
""" % (sys.argv[1], sys.argv[1])

def company2domain():
    try:
        conn = psycopg2.connect(**connection)
        cursor = conn.cursor()
        conn.set_session(autocommit=True)
        cursor.execute(query)
        results = cursor.fetchall()
        for row in results:
            print(f'{row[1]}: {row[0]}')
        conn.close()
        cursor.close()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    company2domain()
