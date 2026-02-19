"""
CDC Lambda Handler - Processes CDC events from MSK via Event Source Mapping.

This Lambda:
1. Receives CDC events from MSK (Debezium from Oracle Exadata on-prem)
2. Caches reference data (PersonInfo, Customer, Organization) to DynamoDB
3. Enriches orders with cached data (phone, email, organization name)
4. Indexes documents to OpenSearch Serverless

DynamoDB Single Table Design:
- Table: enrichment_cache (set via DYNAMODB_TABLE env var from Terraform)
- PK (Partition Key): entity_type  → PERSON_INFO | ORGANIZATION | CUSTOMER
- SK (Sort Key):      entity_id    → person_info_key | organization_code | customer_id

Access Patterns:
- Get person info:   PK=PERSON_INFO,  SK=<person_info_key>
- Get organization:  PK=ORGANIZATION, SK=<organization_code>
- Get customer:      PK=CUSTOMER,     SK=<customer_id>

Environment Variables (all set by Terraform main.tf):
  OPENSEARCH_HOST    hostname only, NO https://  e.g. xxxx.us-east-1.aoss.amazonaws.com
  OPENSEARCH_PORT    443
  OPENSEARCH_SCHEME  https
  OPENSEARCH_AUTH    iam  (SigV4 — no username/password needed for OpenSearch Serverless)
  DYNAMODB_TABLE     table name  e.g. dev-app-enrichment-cache
  AWS_REGION         automatically injected by Lambda runtime
  LOG_LEVEL          INFO | DEBUG | WARNING
"""

import base64
import json
import logging
import os
import socket
from datetime import datetime
from typing import Any, Optional

import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

# ── Environment variables (set by Terraform) ──────────────────────────────────
DYNAMODB_ENDPOINT   = os.environ.get('DYNAMODB_ENDPOINT')        # None = use AWS default
DYNAMODB_TABLE      = os.environ.get('DYNAMODB_TABLE', 'enrichment_cache')
OPENSEARCH_HOST     = os.environ.get('OPENSEARCH_HOST', 'localhost')
OPENSEARCH_PORT     = int(os.environ.get('OPENSEARCH_PORT', '443'))
OPENSEARCH_SCHEME   = os.environ.get('OPENSEARCH_SCHEME', 'https')
OPENSEARCH_AUTH     = os.environ.get('OPENSEARCH_AUTH', 'iam')   # 'iam' or 'basic'
OPENSEARCH_USERNAME = os.environ.get('OPENSEARCH_USERNAME', 'admin')
OPENSEARCH_PASSWORD = os.environ.get('OPENSEARCH_PASSWORD', 'admin')
AWS_REGION          = os.environ.get('AWS_REGION', 'us-east-1')

# ── Startup diagnostics ───────────────────────────────────────────────────────
logger.info("=" * 60)
logger.info("CDC Lambda starting - configuration diagnostics")
logger.info("=" * 60)
logger.info(f"OPENSEARCH_HOST   = {OPENSEARCH_HOST}")
logger.info(f"OPENSEARCH_PORT   = {OPENSEARCH_PORT}")
logger.info(f"OPENSEARCH_AUTH   = {OPENSEARCH_AUTH}")
logger.info(f"DYNAMODB_TABLE    = {DYNAMODB_TABLE}")
logger.info(f"DYNAMODB_ENDPOINT = {DYNAMODB_ENDPOINT}")
logger.info(f"AWS_REGION        = {AWS_REGION}")

try:
    resolved_ips = socket.getaddrinfo(OPENSEARCH_HOST, OPENSEARCH_PORT)
    ip_list = list(set(addr[4][0] for addr in resolved_ips))
    logger.info(f"DNS resolution for {OPENSEARCH_HOST}: {ip_list}")
    for ip in ip_list:
        if ip.startswith('10.') or ip.startswith('172.') or ip.startswith('192.168.'):
            logger.info(f"  {ip} -> PRIVATE IP (VPC endpoint likely working)")
        else:
            logger.warning(f"  {ip} -> PUBLIC IP (check VPC / network policy config)")
except Exception as e:
    logger.error(f"DNS resolution FAILED for {OPENSEARCH_HOST}: {e}")

logger.info("=" * 60)

# ── DynamoDB ──────────────────────────────────────────────────────────────────
_ddb_kwargs = {'region_name': AWS_REGION}
if DYNAMODB_ENDPOINT:
    _ddb_kwargs['endpoint_url']          = DYNAMODB_ENDPOINT
    _ddb_kwargs['aws_access_key_id']     = os.environ.get('AWS_ACCESS_KEY_ID', 'local')
    _ddb_kwargs['aws_secret_access_key'] = os.environ.get('AWS_SECRET_ACCESS_KEY', 'local')
dynamodb    = boto3.resource('dynamodb', **_ddb_kwargs)
cache_table = dynamodb.Table(DYNAMODB_TABLE)

# ── OpenSearch Serverless (SigV4 with service='aoss') ─────────────────────────
if OPENSEARCH_AUTH == 'iam':
    credentials = boto3.Session().get_credentials()
    _auth = AWSV4SignerAuth(credentials, AWS_REGION, 'aoss')
    logger.info(f"OpenSearch: IAM/SigV4 auth → {OPENSEARCH_HOST}:{OPENSEARCH_PORT}")
    opensearch_client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=_auth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        timeout=10
    )
else:
    logger.info(f"OpenSearch: basic auth → {OPENSEARCH_HOST}:{OPENSEARCH_PORT}")
    opensearch_client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        use_ssl=(OPENSEARCH_SCHEME == 'https'),
        verify_certs=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection,
        timeout=10
    )

# ── DynamoDB entity type constants ────────────────────────────────────────────
ENTITY_PERSON_INFO  = 'PERSON_INFO'
ENTITY_ORGANIZATION = 'ORGANIZATION'
ENTITY_CUSTOMER     = 'CUSTOMER'

# ── Shared Painless script — rebuilds searchableText on order docs ─────────────
PAINLESS_REBUILD_ORDER_SEARCHABLE_TEXT = """
    def parts = [];
    if (ctx._source.orderNo != null) parts.add(ctx._source.orderNo);
    if (ctx._source.enterpriseKey != null) parts.add(ctx._source.enterpriseKey);
    if (ctx._source.customerFirstName != null) parts.add(ctx._source.customerFirstName);
    if (ctx._source.customerLastName != null) parts.add(ctx._source.customerLastName);
    if (ctx._source.customerEmailId != null) parts.add(ctx._source.customerEmailId);
    if (ctx._source.customerPhoneNo != null) parts.add(ctx._source.customerPhoneNo);
    if (ctx._source.billTo != null) {
        if (ctx._source.billTo.fullName != null) parts.add(ctx._source.billTo.fullName);
        if (ctx._source.billTo.emailId != null) parts.add(ctx._source.billTo.emailId);
        if (ctx._source.billTo.dayPhone != null) parts.add(ctx._source.billTo.dayPhone);
        if (ctx._source.billTo.eveningPhone != null) parts.add(ctx._source.billTo.eveningPhone);
        if (ctx._source.billTo.mobilePhone != null) parts.add(ctx._source.billTo.mobilePhone);
        if (ctx._source.billTo.city != null) parts.add(ctx._source.billTo.city);
        if (ctx._source.billTo.state != null) parts.add(ctx._source.billTo.state);
        if (ctx._source.billTo.company != null) parts.add(ctx._source.billTo.company);
    }
    if (ctx._source.shipTo != null) {
        if (ctx._source.shipTo.fullName != null) parts.add(ctx._source.shipTo.fullName);
        if (ctx._source.shipTo.emailId != null) parts.add(ctx._source.shipTo.emailId);
        if (ctx._source.shipTo.dayPhone != null) parts.add(ctx._source.shipTo.dayPhone);
        if (ctx._source.shipTo.eveningPhone != null) parts.add(ctx._source.shipTo.eveningPhone);
        if (ctx._source.shipTo.mobilePhone != null) parts.add(ctx._source.shipTo.mobilePhone);
        if (ctx._source.shipTo.city != null) parts.add(ctx._source.shipTo.city);
        if (ctx._source.shipTo.state != null) parts.add(ctx._source.shipTo.state);
        if (ctx._source.shipTo.company != null) parts.add(ctx._source.shipTo.company);
    }
    if (ctx._source.sellerOrganizationName != null) parts.add(ctx._source.sellerOrganizationName);
    if (ctx._source.buyerOrganizationName != null) parts.add(ctx._source.buyerOrganizationName);
    if (ctx._source.sellerOrganizationCode != null) parts.add(ctx._source.sellerOrganizationCode);
    if (ctx._source.buyerOrganizationCode != null) parts.add(ctx._source.buyerOrganizationCode);
    if (ctx._source.customerOrganizationCode != null) parts.add(ctx._source.customerOrganizationCode);
    if (ctx._source.customerOrganizationName != null) parts.add(ctx._source.customerOrganizationName);
    ctx._source.searchableText = String.join(' ', parts);
"""


# =============================================================================
# ENTRY POINT
# =============================================================================

def lambda_handler(event: dict, context: Any) -> dict:
    """
    MSK trigger event structure:
    {
        "eventSource": "aws:kafka",
        "records": {
            "sterling.public.yfs_customer-0": [
                { "topic": "...", "value": "<base64 Debezium JSON>" }
            ]
        }
    }
    """
    try:
        logger.info(f"Incoming event: {json.dumps(event, default=str)[:5000]}")

        if event.get('eventSource') == 'aws:kafka' or 'records' in event:
            return process_msk_event(event)

        # Direct invocation for testing
        return process_single_event(
            table=event.get('table', '').upper(),
            operation=event.get('operation', 'c'),
            payload=event.get('payload', {}),
            source_timestamp=event.get('sourceTimestamp')
        )
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        return {'statusCode': 500, 'body': str(e)}


TOPIC_TABLE_MAP = {
    'yfs_order_header': 'YFS_ORDER_HEADER',
    'yfs_person_info':  'YFS_PERSON_INFO',
    'yfs_customer':     'YFS_CUSTOMER',
    'yfs_organization': 'YFS_ORGANIZATION',
    'yfs_order_line':   'YFS_ORDER_LINE',
}


def extract_table_from_topic(topic: str) -> str:
    table_part = topic.rsplit('.', 1)[-1].lower()
    return TOPIC_TABLE_MAP.get(table_part, table_part.upper())


def process_msk_event(event: dict) -> dict:
    processed, errors = 0, 0
    for topic_partition, messages in event.get('records', {}).items():
        for msg in messages:
            try:
                topic   = msg.get('topic', topic_partition.rsplit('-', 1)[0])
                table   = extract_table_from_topic(topic)
                payload_raw    = json.loads(base64.b64decode(msg['value']).decode('utf-8'))
                operation      = payload_raw.get('op', 'c')
                source_ts      = payload_raw.get('ts_ms')
                raw_data       = payload_raw.get('before' if operation == 'd' else 'after') or {}
                payload        = {k.upper(): v for k, v in raw_data.items()}

                logger.info(f"Processing {operation} on {table} from {topic}")
                logger.info(f"Payload keys: {list(payload.keys())}")
                logger.info(f"Payload sample: {json.dumps(payload, default=str)[:2000]}")

                result = process_single_event(table, operation, payload, source_ts)
                logger.info(f"Result for {table}: {result}")
                processed += 1
            except Exception as e:
                errors += 1
                logger.error(f"Error in {topic_partition}: {e}", exc_info=True)

    logger.info(f"Batch complete: {processed} processed, {errors} errors")
    return {'statusCode': 200, 'body': f'Processed {processed}, errors {errors}'}


def process_single_event(table: str, operation: str, payload: dict, source_timestamp=None) -> dict:
    if   'YFS_ORDER_HEADER'  in table: return process_order(payload, operation, source_timestamp)
    elif 'YFS_ORDER_LINE'    in table: return process_order_line(payload, operation, source_timestamp)
    elif 'YFS_PERSON_INFO'   in table: return process_person_info(payload, operation)
    elif 'YFS_CUSTOMER'      in table: return process_customer(payload, operation, source_timestamp)
    elif 'YFS_ORGANIZATION'  in table: return process_organization(payload, operation)
    else:
        logger.warning(f"Unknown table: {table}")
        return {'statusCode': 400, 'body': f'Unknown table: {table}'}


# =============================================================================
# REFERENCE DATA — PersonInfo
# =============================================================================

def process_person_info(payload: dict, operation: str) -> dict:
    """Phase 1: Cache → Phase 2: Fan-out orders → Phase 3: Fan-out organizations"""
    person_info_key = get_value(payload, 'PERSON_INFO_KEY')
    if not person_info_key:
        logger.warning(f"Missing PERSON_INFO_KEY. Keys: {list(payload.keys())}")
        return {'statusCode': 400, 'body': 'Missing PERSON_INFO_KEY'}

    if operation == 'd':
        cache_table.delete_item(Key={'PK': ENTITY_PERSON_INFO, 'SK': person_info_key})
        logger.info(f"Phase 1: Deleted PersonInfo {person_info_key} from cache")
    else:
        item = {k: v for k, v in {
            'PK': ENTITY_PERSON_INFO, 'SK': person_info_key,
            'personInfoKey': person_info_key,
            'firstName':    get_value(payload, 'FIRST_NAME'),
            'lastName':     get_value(payload, 'LAST_NAME'),
            'middleName':   get_value(payload, 'MIDDLE_NAME'),
            'company':      get_value(payload, 'COMPANY'),
            'addressLine1': get_value(payload, 'ADDRESS_LINE1'),
            'addressLine2': get_value(payload, 'ADDRESS_LINE2'),
            'addressLine3': get_value(payload, 'ADDRESS_LINE3'),
            'city':         get_value(payload, 'CITY'),
            'state':        get_value(payload, 'STATE'),
            'zipCode':      get_value(payload, 'ZIP_CODE'),
            'country':      get_value(payload, 'COUNTRY'),
            'emailId':      get_value(payload, 'EMAILID'),
            'dayPhone':     get_value(payload, 'DAY_PHONE'),
            'eveningPhone': get_value(payload, 'EVENING_PHONE'),
            'mobilePhone':  get_value(payload, 'MOBILE_PHONE'),
            'updatedAt':    datetime.utcnow().isoformat()
        }.items() if v is not None}
        logger.info(f"Phase 1: Writing PersonInfo {person_info_key} to DynamoDB, fields={list(item.keys())}")
        try:
            cache_table.put_item(Item=item)
            logger.info(f"Phase 1: DynamoDB SUCCESS for PersonInfo {person_info_key}")
        except Exception as e:
            logger.error(f"Phase 1: DynamoDB FAILED for PersonInfo {person_info_key}: {e}", exc_info=True)
            raise

    update_orders_with_person_info(person_info_key, payload, operation)
    update_organizations_with_person_info(person_info_key, payload, operation)
    return {'statusCode': 200, 'body': f'Processed person info: {person_info_key}'}


# =============================================================================
# REFERENCE DATA — Customer
# =============================================================================

def process_customer(payload: dict, operation: str, source_timestamp=None) -> dict:
    """Phase 1: Cache → Phase 2: Index to OpenSearch customers"""
    customer_id  = get_value(payload, 'CUSTOMER_ID')
    customer_key = get_value(payload, 'CUSTOMER_KEY')
    if not customer_id:
        return {'statusCode': 400, 'body': 'Missing CUSTOMER_ID'}

    if operation == 'd':
        cache_table.delete_item(Key={'PK': ENTITY_CUSTOMER, 'SK': customer_id})
        logger.info(f"Phase 1: Deleted Customer {customer_id} from cache")
    else:
        item = {k: v for k, v in {
            'PK': ENTITY_CUSTOMER, 'SK': customer_id,
            'customerKey':       customer_key,
            'customerId':        customer_id,
            'customerType':      get_value(payload, 'CUSTOMER_TYPE'),
            'organizationCode':  get_value(payload, 'ORGANIZATION_CODE'),
            'billingAddressKey': get_value(payload, 'BILLING_ADDRESS_KEY'),
            'contactAddressKey': get_value(payload, 'CONTACT_ADDRESS_KEY'),
            'status':            get_value(payload, 'STATUS'),
            'updatedAt':         datetime.utcnow().isoformat()
        }.items() if v is not None}
        logger.info(f"Phase 1: Writing Customer {customer_id} to DynamoDB, fields={list(item.keys())}")
        try:
            cache_table.put_item(Item=item)
            logger.info(f"Phase 1: DynamoDB SUCCESS for Customer {customer_id}")
        except Exception as e:
            logger.error(f"Phase 1: DynamoDB FAILED for Customer {customer_id}: {e}", exc_info=True)
            raise

    index_customer(customer_key, customer_id, payload, operation, source_timestamp)
    return {'statusCode': 200, 'body': f'Processed customer: {customer_id}'}


def index_customer(customer_key, customer_id, payload, operation, source_timestamp):
    try:
        if not customer_key:
            logger.warning(f"Missing CUSTOMER_KEY for customer {customer_id}, skipping OpenSearch")
            return
        if operation == 'd':
            opensearch_client.delete(index='customers', id=customer_key, ignore=[404])
            logger.info(f"Phase 2: Deleted customer {customer_key} from customers index")
            return

        org_code = get_value(payload, 'ORGANIZATION_CODE')
        doc = {k: v for k, v in {
            'customerKey':       customer_key,
            'customerId':        customer_id,
            'customerType':      get_value(payload, 'CUSTOMER_TYPE'),
            'organizationCode':  org_code,
            'status':            get_value(payload, 'STATUS'),
            'createdTimestamp':  get_timestamp_value(payload, 'CREATETS'),
            'modifiedTimestamp': get_timestamp_value(payload, 'MODIFYTS'),
            'cdcOperation':      operation,
            'cdcTimestamp':      source_timestamp,
            'indexedAt':         int(datetime.utcnow().timestamp() * 1000),
        }.items() if v is not None}

        searchable = [customer_id, org_code, get_value(payload, 'CUSTOMER_TYPE'), get_value(payload, 'STATUS')]
        if org_code:
            org = get_cached_organization(org_code)
            if org:
                doc['organization'] = {k: org.get(k) for k in ('organizationKey', 'organizationCode', 'organizationName') if org.get(k)}
                searchable.append(org.get('organizationName'))

        doc['searchableText'] = ' '.join(filter(None, searchable))
        resp = opensearch_client.index(index='customers', id=customer_key, body=doc, refresh=False)
        logger.info(f"Phase 2: customers index {customer_key}: {resp.get('result')}")
    except Exception as e:
        logger.error(f"Phase 2 FAILED indexing customer {customer_key}: {e}", exc_info=True)


# =============================================================================
# REFERENCE DATA — Organization
# =============================================================================

def process_organization(payload: dict, operation: str) -> dict:
    """Phase 1: Cache → Phase 2: Fan-out orders → Phase 3: Index to OpenSearch"""
    org_code = get_value(payload, 'ORGANIZATION_CODE')
    if not org_code:
        return {'statusCode': 400, 'body': 'Missing ORGANIZATION_CODE'}

    org_name            = get_value(payload, 'ORGANIZATION_NAME')
    org_key             = get_value(payload, 'ORGANIZATION_KEY')
    corporate_addr_key  = get_value(payload, 'CORPORATE_ADDRESS_KEY')
    contact_addr_key    = get_value(payload, 'CONTACT_ADDRESS_KEY')

    if operation == 'd':
        cache_table.delete_item(Key={'PK': ENTITY_ORGANIZATION, 'SK': org_code})
        logger.info(f"Phase 1: Deleted Organization {org_code} from cache")
    else:
        item = {k: v for k, v in {
            'PK': ENTITY_ORGANIZATION, 'SK': org_code,
            'organizationKey':        org_key,
            'organizationCode':       org_code,
            'organizationName':       org_name,
            'parentOrganizationCode': get_value(payload, 'PARENT_ORGANIZATION_CODE'),
            'primaryEnterpriseKey':   get_value(payload, 'PRIMARY_ENTERPRISE_KEY'),
            'corporateAddressKey':    corporate_addr_key,
            'contactAddressKey':      contact_addr_key,
            'updatedAt':              datetime.utcnow().isoformat()
        }.items() if v is not None}
        logger.info(f"Phase 1: Writing Organization {org_code} to DynamoDB, name={org_name}")
        try:
            cache_table.put_item(Item=item)
            logger.info(f"Phase 1: DynamoDB SUCCESS for Organization {org_code}")
        except Exception as e:
            logger.error(f"Phase 1: DynamoDB FAILED for Organization {org_code}: {e}", exc_info=True)
            raise

    update_orders_with_organization(org_code, org_name, operation)
    index_organization(org_code, org_key, org_name, payload, operation, corporate_addr_key, contact_addr_key)
    return {'statusCode': 200, 'body': f'Processed organization: {org_code}'}


def index_organization(org_code, org_key, org_name, payload, operation, corporate_addr_key, contact_addr_key):
    try:
        if operation == 'd':
            opensearch_client.delete(index='organizations', id=org_code, ignore=[404])
            logger.info(f"Phase 3: Deleted organization {org_code} from OpenSearch")
            return

        doc = {k: v for k, v in {
            'organizationKey':        org_key,
            'organizationCode':       org_code,
            'organizationName':       org_name,
            'parentOrganizationCode': get_value(payload, 'PARENT_ORGANIZATION_CODE'),
            'corporateAddressKey':    corporate_addr_key,
            'contactAddressKey':      contact_addr_key,
            'cdcOperation':           operation,
            'indexedAt':              int(datetime.utcnow().timestamp() * 1000),
        }.items() if v is not None}

        if corporate_addr_key:
            addr = get_cached_person_info(corporate_addr_key)
            if addr:
                for f in ('addressLine1', 'city', 'state', 'zipCode', 'country'):
                    if addr.get(f): doc[f] = addr[f]

        if contact_addr_key:
            contact = get_cached_person_info(contact_addr_key)
            if contact:
                name = build_full_name(contact)
                if name:               doc['contactName']  = name
                if contact.get('emailId'): doc['contactEmail'] = contact['emailId']
                phone = get_primary_phone(contact)
                if phone: doc['contactPhone'] = phone

        doc['searchableText'] = ' '.join(filter(None, [
            doc.get('organizationCode'), doc.get('organizationName'),
            doc.get('addressLine1'),     doc.get('city'),
            doc.get('state'),            doc.get('zipCode'),
            doc.get('country'),          doc.get('contactName'),
            doc.get('contactEmail'),     doc.get('contactPhone'),
        ]))

        resp = opensearch_client.index(index='organizations', id=org_code, body=doc, refresh=False)
        logger.info(f"Phase 3: organizations index {org_code}: {resp.get('result')}")
    except Exception as e:
        logger.error(f"Phase 3 FAILED for Organization {org_code}: {e}", exc_info=True)


# =============================================================================
# FAN-OUT — update_by_query helpers
# =============================================================================

def update_orders_with_person_info(person_info_key: str, payload: dict, operation: str) -> None:
    """Update all orders where billToKey or shipToKey matches this PersonInfo."""
    try:
        if operation == 'd':
            params = {k: None for k in ['fullName','emailId','dayPhone','eveningPhone','mobilePhone','city','state','zipCode','country','company','addressLine1']}
        else:
            params = {
                'fullName':     build_full_name_from_payload(payload),
                'emailId':      get_value(payload, 'EMAILID'),
                'dayPhone':     get_value(payload, 'DAY_PHONE'),
                'eveningPhone': get_value(payload, 'EVENING_PHONE'),
                'mobilePhone':  get_value(payload, 'MOBILE_PHONE'),
                'city':         get_value(payload, 'CITY'),
                'state':        get_value(payload, 'STATE'),
                'zipCode':      get_value(payload, 'ZIP_CODE'),
                'country':      get_value(payload, 'COUNTRY'),
                'company':      get_value(payload, 'COMPANY'),
                'addressLine1': get_value(payload, 'ADDRESS_LINE1'),
            }

        for address_field, term_field in [('billTo', 'billToKey'), ('shipTo', 'shipToKey')]:
            script = f"""
                if (ctx._source.{address_field} == null) {{ ctx._source.{address_field} = [:]; }}
                ctx._source.{address_field}.fullName = params.fullName;
                ctx._source.{address_field}.emailId = params.emailId;
                ctx._source.{address_field}.dayPhone = params.dayPhone;
                ctx._source.{address_field}.eveningPhone = params.eveningPhone;
                ctx._source.{address_field}.mobilePhone = params.mobilePhone;
                ctx._source.{address_field}.city = params.city;
                ctx._source.{address_field}.state = params.state;
                ctx._source.{address_field}.zipCode = params.zipCode;
                ctx._source.{address_field}.country = params.country;
                ctx._source.{address_field}.company = params.company;
                ctx._source.{address_field}.addressLine1 = params.addressLine1;
            """ + PAINLESS_REBUILD_ORDER_SEARCHABLE_TEXT

            r = opensearch_client.update_by_query(
                index='orders', conflicts='proceed', refresh=False,
                body={"query": {"term": {term_field: person_info_key}},
                      "script": {"source": script, "lang": "painless", "params": params}}
            )
            if r.get('updated', 0):
                logger.info(f"Phase 2: Updated {r['updated']} orders ({term_field}) for PersonInfo {person_info_key}")

    except Exception as e:
        logger.warning(f"Phase 2 (PersonInfo fan-out) failed for {person_info_key}: {e}")


def update_orders_with_organization(org_code: str, org_name: Optional[str], operation: str) -> None:
    """Update all orders where seller/buyer/customerOrganizationCode matches."""
    try:
        new_name = None if operation == 'd' else org_name
        for name_field, code_field in [
            ('sellerOrganizationName',   'sellerOrganizationCode'),
            ('buyerOrganizationName',    'buyerOrganizationCode'),
            ('customerOrganizationName', 'customerOrganizationCode'),
        ]:
            r = opensearch_client.update_by_query(
                index='orders', conflicts='proceed', refresh=False,
                body={"query": {"term": {code_field: org_code}},
                      "script": {"source": f"ctx._source.{name_field} = params.name;" + PAINLESS_REBUILD_ORDER_SEARCHABLE_TEXT,
                                 "lang": "painless", "params": {"name": new_name}}}
            )
            if r.get('updated', 0):
                logger.info(f"Phase 2: Updated {r['updated']} orders ({name_field}) for org {org_code}")
    except Exception as e:
        logger.warning(f"Phase 2 (Organization fan-out) failed for {org_code}: {e}")


def update_organizations_with_person_info(person_info_key: str, payload: dict, operation: str) -> None:
    """Update organizations index when a PersonInfo record changes."""
    try:
        rebuild_org = """
            def parts = [];
            if (ctx._source.organizationCode != null) parts.add(ctx._source.organizationCode);
            if (ctx._source.organizationName != null) parts.add(ctx._source.organizationName);
            if (ctx._source.addressLine1 != null) parts.add(ctx._source.addressLine1);
            if (ctx._source.city != null) parts.add(ctx._source.city);
            if (ctx._source.state != null) parts.add(ctx._source.state);
            if (ctx._source.zipCode != null) parts.add(ctx._source.zipCode);
            if (ctx._source.country != null) parts.add(ctx._source.country);
            if (ctx._source.contactName != null) parts.add(ctx._source.contactName);
            if (ctx._source.contactEmail != null) parts.add(ctx._source.contactEmail);
            if (ctx._source.contactPhone != null) parts.add(ctx._source.contactPhone);
            ctx._source.searchableText = String.join(' ', parts);
        """

        if operation == 'd':
            addr_params    = {k: None for k in ['addressLine1','city','state','zipCode','country']}
            contact_params = {k: None for k in ['contactName','contactEmail','contactPhone']}
        else:
            addr_params = {
                'addressLine1': get_value(payload, 'ADDRESS_LINE1'),
                'city':         get_value(payload, 'CITY'),
                'state':        get_value(payload, 'STATE'),
                'zipCode':      get_value(payload, 'ZIP_CODE'),
                'country':      get_value(payload, 'COUNTRY'),
            }
            contact_params = {
                'contactName':  build_full_name_from_payload(payload),
                'contactEmail': get_value(payload, 'EMAILID'),
                'contactPhone': (get_value(payload, 'MOBILE_PHONE') or
                                 get_value(payload, 'DAY_PHONE') or
                                 get_value(payload, 'EVENING_PHONE')),
            }

        opensearch_client.update_by_query(
            index='organizations', conflicts='proceed', refresh=False,
            body={"query": {"term": {"corporateAddressKey": person_info_key}},
                  "script": {"source": "ctx._source.addressLine1=params.addressLine1; ctx._source.city=params.city; ctx._source.state=params.state; ctx._source.zipCode=params.zipCode; ctx._source.country=params.country;" + rebuild_org,
                             "lang": "painless", "params": addr_params}}
        )
        opensearch_client.update_by_query(
            index='organizations', conflicts='proceed', refresh=False,
            body={"query": {"term": {"contactAddressKey": person_info_key}},
                  "script": {"source": "ctx._source.contactName=params.contactName; ctx._source.contactEmail=params.contactEmail; ctx._source.contactPhone=params.contactPhone;" + rebuild_org,
                             "lang": "painless", "params": contact_params}}
        )
    except Exception as e:
        logger.warning(f"Organization fan-out failed for PersonInfo {person_info_key}: {e}")


# =============================================================================
# ORDER PROCESSING
# =============================================================================

def process_order(payload: dict, operation: str, source_timestamp: Optional[int]) -> dict:
    order_header_key = get_value(payload, 'ORDER_HEADER_KEY')
    if not order_header_key:
        return {'statusCode': 400, 'body': 'Missing ORDER_HEADER_KEY'}

    if operation == 'd':
        opensearch_client.delete(index='orders', id=order_header_key, ignore=[404])
        logger.info(f"Deleted order {order_header_key}")
        return {'statusCode': 200, 'body': f'Deleted order: {order_header_key}'}

    doc = transform_order(payload, operation, source_timestamp)

    bill_to_key = get_value(payload, 'BILL_TO_KEY')
    if bill_to_key:
        bt = get_cached_person_info(bill_to_key)
        if bt:
            doc['billTo'] = {k: v for k, v in {
                'personInfoKey': bill_to_key,
                'firstName':  bt.get('firstName'),     'lastName':  bt.get('lastName'),
                'fullName':   build_full_name(bt),      'emailId':   bt.get('emailId'),
                'dayPhone':   bt.get('dayPhone'),        'eveningPhone': bt.get('eveningPhone'),
                'mobilePhone':bt.get('mobilePhone'),    'company':   bt.get('company'),
                'addressLine1':bt.get('addressLine1'),  'city':      bt.get('city'),
                'state':      bt.get('state'),           'zipCode':   bt.get('zipCode'),
                'country':    bt.get('country'),
            }.items() if v is not None}

    ship_to_key = get_value(payload, 'SHIP_TO_KEY')
    if ship_to_key:
        st = get_cached_person_info(ship_to_key)
        if st:
            doc['shipTo'] = {k: v for k, v in {
                'personInfoKey': ship_to_key,
                'firstName':  st.get('firstName'),     'lastName':  st.get('lastName'),
                'fullName':   build_full_name(st),      'emailId':   st.get('emailId'),
                'dayPhone':   st.get('dayPhone'),        'eveningPhone': st.get('eveningPhone'),
                'mobilePhone':st.get('mobilePhone'),    'company':   st.get('company'),
                'addressLine1':st.get('addressLine1'),  'city':      st.get('city'),
                'state':      st.get('state'),           'zipCode':   st.get('zipCode'),
                'country':    st.get('country'),
            }.items() if v is not None}

    seller_org = get_cached_organization(get_value(payload, 'SELLER_ORGANIZATION_CODE') or '')
    if seller_org and seller_org.get('organizationName'):
        doc['sellerOrganizationName'] = seller_org['organizationName']

    buyer_org = get_cached_organization(get_value(payload, 'BUYER_ORGANIZATION_CODE') or '')
    if buyer_org and buyer_org.get('organizationName'):
        doc['buyerOrganizationName'] = buyer_org['organizationName']

    bill_to_id = get_value(payload, 'BILL_TO_ID')
    if bill_to_id:
        customer = get_cached_customer(bill_to_id)
        if customer:
            doc['customer'] = {k: customer.get(k) for k in ('customerId','customerKey','customerType','organizationCode') if customer.get(k)}
            cust_org_code = customer.get('organizationCode')
            if cust_org_code:
                doc['customerOrganizationCode'] = cust_org_code
                cust_org = get_cached_organization(cust_org_code)
                if cust_org and cust_org.get('organizationName'):
                    doc['customerOrganizationName'] = cust_org['organizationName']

    doc['searchableText'] = build_order_searchable_text(doc)

    try:
        resp = opensearch_client.index(index='orders', id=order_header_key, body=doc, refresh=False)
        logger.info(f"Indexed order {order_header_key}: {resp.get('result')}")
    except Exception as e:
        logger.error(f"OpenSearch order index FAILED for {order_header_key}: {e}", exc_info=True)
        raise

    return {'statusCode': 200, 'body': f'Indexed order: {order_header_key}'}


def transform_order(payload: dict, operation: str, source_timestamp: Optional[int]) -> dict:
    order_date = get_value(payload, 'ORDER_DATE')
    if order_date and isinstance(order_date, (int, float)):
        order_date = datetime.utcfromtimestamp(order_date / 1000).isoformat()
    return {k: v for k, v in {
        'orderHeaderKey':         get_value(payload, 'ORDER_HEADER_KEY'),
        'orderNo':                get_value(payload, 'ORDER_NO'),
        'enterpriseKey':          get_value(payload, 'ENTERPRISE_KEY'),
        'documentType':           get_value(payload, 'DOCUMENT_TYPE'),
        'orderDate':              order_date,
        'reqDeliveryDate':        get_timestamp_value(payload, 'REQ_DELIVERY_DATE'),
        'orderType':              get_value(payload, 'ORDER_TYPE'),
        'totalAmount':            get_float_value(payload, 'TOTAL_AMOUNT'),
        'currency':               get_value(payload, 'CURRENCY'),
        'paymentStatus':          get_value(payload, 'PAYMENT_STATUS'),
        'priceProgramKey':        get_value(payload, 'PRICE_PROGRAM_KEY'),
        'sellerOrganizationCode': get_value(payload, 'SELLER_ORGANIZATION_CODE'),
        'buyerOrganizationCode':  get_value(payload, 'BUYER_ORGANIZATION_CODE'),
        'billToKey':              get_value(payload, 'BILL_TO_KEY'),
        'billToId':               get_value(payload, 'BILL_TO_ID'),
        'shipToKey':              get_value(payload, 'SHIP_TO_KEY'),
        'customerEmailId':        get_value(payload, 'CUSTOMER_EMAILID'),
        'customerFirstName':      get_value(payload, 'CUSTOMER_FIRST_NAME'),
        'customerLastName':       get_value(payload, 'CUSTOMER_LAST_NAME'),
        'customerPhoneNo':        get_value(payload, 'CUSTOMER_PHONE_NO'),
        'createdTimestamp':       get_timestamp_value(payload, 'CREATETS'),
        'modifiedTimestamp':      get_timestamp_value(payload, 'MODIFYTS'),
        'cdcOperation':           operation,
        'cdcTimestamp':           source_timestamp,
        'indexedAt':              int(datetime.utcnow().timestamp() * 1000),
    }.items() if v is not None}


# =============================================================================
# ORDER LINE PROCESSING
# =============================================================================

def process_order_line(payload: dict, operation: str, source_timestamp: Optional[int]) -> dict:
    order_line_key = get_value(payload, 'ORDER_LINE_KEY')
    if not order_line_key:
        return {'statusCode': 400, 'body': 'Missing ORDER_LINE_KEY'}

    if operation == 'd':
        opensearch_client.delete(index='order-lines', id=order_line_key, ignore=[404])
        return {'statusCode': 200, 'body': f'Deleted order line: {order_line_key}'}

    doc = transform_order_line(payload, operation, source_timestamp)
    doc['searchableText'] = ' '.join(filter(None, [
        doc.get('itemId'),            doc.get('itemDescription'),
        doc.get('itemShortDescription'), doc.get('customerItem'),
        doc.get('customerPoNo'),      doc.get('manufacturerName'),
        doc.get('manufacturerItem'),  doc.get('productClass'),
        doc.get('productLine'),       doc.get('upcCode'),
        doc.get('supplierItem'),      doc.get('serialNo'),
    ]))

    try:
        resp = opensearch_client.index(index='order-lines', id=order_line_key, body=doc, refresh=False)
        logger.info(f"Indexed order line {order_line_key}: {resp.get('result')}")
    except Exception as e:
        logger.error(f"OpenSearch order-line index FAILED for {order_line_key}: {e}", exc_info=True)
        raise

    return {'statusCode': 200, 'body': f'Indexed order line: {order_line_key}'}


def transform_order_line(payload: dict, operation: str, source_timestamp: Optional[int]) -> dict:
    return {k: v for k, v in {
        'orderLineKey':    get_value(payload, 'ORDER_LINE_KEY'),
        'orderHeaderKey':  get_value(payload, 'ORDER_HEADER_KEY'),
        'primeLineNo':     get_int_value(payload, 'PRIME_LINE_NO'),
        'subLineNo':       get_int_value(payload, 'SUB_LINE_NO'),
        'lineType':        get_value(payload, 'LINE_TYPE'),
        'orderClass':      get_value(payload, 'ORDER_CLASS'),
        'lineSeqNo':       get_value(payload, 'LINE_SEQ_NO'),
        'itemId':          get_value(payload, 'ITEM_ID'),
        'alternateItemId': get_value(payload, 'ALTERNATE_ITEM_ID'),
        'uom':             get_value(payload, 'UOM'),
        'productClass':    get_value(payload, 'PRODUCT_CLASS'),
        'productLine':     get_value(payload, 'PRODUCT_LINE'),
        'itemDescription': get_value(payload, 'ITEM_DESCRIPTION'),
        'itemShortDescription': get_value(payload, 'ITEM_SHORT_DESCRIPTION'),
        'customerItem':    get_value(payload, 'CUSTOMER_ITEM'),
        'customerItemDescription': get_value(payload, 'CUSTOMER_ITEM_DESCRIPTION'),
        'supplierItem':    get_value(payload, 'SUPPLIER_ITEM'),
        'supplierItemDescription': get_value(payload, 'SUPPLIER_ITEM_DESCRIPTION'),
        'supplierCode':    get_value(payload, 'SUPPLIER_CODE'),
        'upcCode':         get_value(payload, 'UPC_CODE'),
        'manufacturerName': get_value(payload, 'MANUFACTURER_NAME'),
        'manufacturerItem': get_value(payload, 'MANUFACTURER_ITEM'),
        'countryOfOrigin': get_value(payload, 'COUNTRY_OF_ORIGIN'),
        'unitPrice':       get_float_value(payload, 'UNIT_PRICE'),
        'listPrice':       get_float_value(payload, 'LIST_PRICE'),
        'retailPrice':     get_float_value(payload, 'RETAIL_PRICE'),
        'unitCost':        get_float_value(payload, 'UNIT_COST'),
        'costCurrency':    get_value(payload, 'COST_CURRENCY'),
        'discountPercentage': get_float_value(payload, 'DISCOUNT_PERCENTAGE'),
        'discountType':    get_value(payload, 'DISCOUNT_TYPE'),
        'otherCharges':    get_float_value(payload, 'OTHER_CHARGES'),
        'lineTotal':       get_float_value(payload, 'LINE_TOTAL'),
        'invoicedLineTotal': get_float_value(payload, 'INVOICED_LINE_TOTAL'),
        'tax':             get_float_value(payload, 'TAX'),
        'orderedQty':      get_float_value(payload, 'ORDERED_QTY'),
        'originalOrderedQty': get_float_value(payload, 'ORIGINAL_ORDERED_QTY'),
        'committedQuantity': get_float_value(payload, 'COMMITTED_QUANTITY'),
        'shippedQuantity': get_float_value(payload, 'SHIPPED_QUANTITY'),
        'invoicedQuantity': get_float_value(payload, 'INVOICED_QUANTITY'),
        'receivedQuantity': get_float_value(payload, 'RECEIVED_QUANTITY'),
        'settledQuantity': get_float_value(payload, 'SETTLED_QUANTITY'),
        'settledAmount':   get_float_value(payload, 'SETTLED_AMOUNT'),
        'shipnodeKey':     get_value(payload, 'SHIPNODE_KEY'),
        'shipToKey':       get_value(payload, 'SHIP_TO_KEY'),
        'scac':            get_value(payload, 'SCAC'),
        'carrierServiceCode': get_value(payload, 'CARRIER_SERVICE_CODE'),
        'deliveryMethod':  get_value(payload, 'DELIVERY_METHOD'),
        'fulfillmentType': get_value(payload, 'FULFILLMENT_TYPE'),
        'reqDeliveryDate': get_timestamp_value(payload, 'REQ_DELIVERY_DATE'),
        'reqShipDate':     get_timestamp_value(payload, 'REQ_SHIP_DATE'),
        'holdFlag':        get_value(payload, 'HOLD_FLAG'),
        'taxableFlag':     get_value(payload, 'TAXABLE_FLAG'),
        'customerPoNo':    get_value(payload, 'CUSTOMER_PO_NO'),
        'customerPoLineNo': get_value(payload, 'CUSTOMER_PO_LINE_NO'),
        'departmentCode':  get_value(payload, 'DEPARTMENT_CODE'),
        'segment':         get_value(payload, 'SEGMENT'),
        'itemWeight':      get_float_value(payload, 'ITEM_WEIGHT'),
        'serialNo':        get_value(payload, 'SERIAL_NO'),
        'harmonizedCode':  get_value(payload, 'HARMONIZED_CODE'),
        'createdTimestamp': get_timestamp_value(payload, 'CREATETS'),
        'modifiedTimestamp': get_timestamp_value(payload, 'MODIFYTS'),
        'createUserId':    get_value(payload, 'CREATEUSERID'),
        'modifyUserId':    get_value(payload, 'MODIFYUSERID'),
        'cdcOperation':    operation,
        'cdcTimestamp':    source_timestamp,
        'indexedAt':       int(datetime.utcnow().timestamp() * 1000),
    }.items() if v is not None}


# =============================================================================
# CACHE LOOKUPS
# =============================================================================

def get_cached_person_info(key: str) -> Optional[dict]:
    try:
        r = cache_table.get_item(Key={'PK': ENTITY_PERSON_INFO, 'SK': key})
        item = r.get('Item')
        return {k: v for k, v in item.items() if k not in ('PK','SK','updatedAt')} if item else None
    except Exception as e:
        logger.warning(f"Cache miss PersonInfo {key}: {e}")
        return None

def get_cached_organization(code: str) -> Optional[dict]:
    try:
        r = cache_table.get_item(Key={'PK': ENTITY_ORGANIZATION, 'SK': code})
        item = r.get('Item')
        return {k: v for k, v in item.items() if k not in ('PK','SK','updatedAt')} if item else None
    except Exception as e:
        logger.warning(f"Cache miss Organization {code}: {e}")
        return None

def get_cached_customer(customer_id: str) -> Optional[dict]:
    try:
        r = cache_table.get_item(Key={'PK': ENTITY_CUSTOMER, 'SK': customer_id})
        item = r.get('Item')
        return {k: v for k, v in item.items() if k not in ('PK','SK','updatedAt')} if item else None
    except Exception as e:
        logger.warning(f"Cache miss Customer {customer_id}: {e}")
        return None


# =============================================================================
# UTILITIES
# =============================================================================

def build_full_name(p: dict) -> Optional[str]:
    return ' '.join(x for x in (p.get('firstName'), p.get('middleName'), p.get('lastName')) if x) or None

def build_full_name_from_payload(payload: dict) -> Optional[str]:
    return ' '.join(x for x in (get_value(payload, 'FIRST_NAME'), get_value(payload, 'MIDDLE_NAME'), get_value(payload, 'LAST_NAME')) if x) or None

def get_primary_phone(p: dict) -> Optional[str]:
    return p.get('mobilePhone') or p.get('dayPhone') or p.get('eveningPhone')

def build_order_searchable_text(order: dict) -> str:
    parts = [order.get(f) for f in ('orderNo','enterpriseKey','customerFirstName','customerLastName','customerEmailId','customerPhoneNo','sellerOrganizationName','buyerOrganizationName','sellerOrganizationCode','buyerOrganizationCode','customerOrganizationCode','customerOrganizationName')]
    for obj in (order.get('billTo'), order.get('shipTo')):
        if obj:
            parts += [obj.get(f) for f in ('fullName','emailId','dayPhone','eveningPhone','mobilePhone','company','city','state')]
    return ' '.join(filter(None, parts))

def get_value(payload: dict, key: str) -> Optional[str]:
    v = payload.get(key)
    if v is None: return None
    s = str(v).strip()
    return s if s else None

def get_float_value(payload: dict, key: str) -> Optional[float]:
    v = payload.get(key)
    try: return float(v) if v is not None else None
    except (ValueError, TypeError): return None

def get_int_value(payload: dict, key: str) -> Optional[int]:
    v = payload.get(key)
    try: return int(v) if v is not None else None
    except (ValueError, TypeError): return None

def get_timestamp_value(payload: dict, key: str) -> Optional[int]:
    """Convert Debezium timestamps (microseconds) → epoch milliseconds."""
    v = payload.get(key)
    if v is None: return None
    try:
        ts = int(v)
        if ts > 1e15:  return ts // 1000   # microseconds → ms
        if ts > 1e12:  return ts            # already ms
        return ts * 1000                    # seconds → ms
    except (ValueError, TypeError):
        return None
