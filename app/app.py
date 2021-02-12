
import logging
import os
import pyqrcode
import requests
import traceback
import asyncio
from asyncio.base_events import Server
from aiohttp import web
from aiohttp.web_routedef import RouteTableDef
import jinja2
import aiohttp_jinja2

from verity_sdk.handlers import Handlers
from verity_sdk.protocols.v0_6.IssuerSetup import IssuerSetup
from verity_sdk.protocols.v0_6.UpdateConfigs import UpdateConfigs
from verity_sdk.protocols.v0_6.UpdateEndpoint import UpdateEndpoint
from verity_sdk.protocols.v0_6.WriteCredentialDefinition import WriteCredentialDefinition
from verity_sdk.protocols.v0_6.WriteSchema import WriteSchema
from verity_sdk.protocols.v0_7.Provision import Provision
from verity_sdk.protocols.v1_0.Connecting import Connecting
from verity_sdk.protocols.v1_0.IssueCredential import IssueCredential
from verity_sdk.protocols.v1_0.PresentProof import PresentProof
from verity_sdk.protocols.v1_0.Relationship import Relationship
from verity_sdk.protocols.v1_0.CommittedAnswer import CommittedAnswer
from verity_sdk.utils.Context import Context
from indy.wallet import delete_wallet
from indy import crypto
from indy.error import WalletNotFoundError, WalletAlreadyOpenedError

import dbhelper
from helper import *

logging_format = "[%(asctime)s] %(process)d-%(levelname)s "
logging_format += "%(module)s::%(funcName)s():l%(lineno)d: "
logging_format += "%(message)s"

logging.basicConfig(
    format=logging_format,
    level=logging.DEBUG
)
log = logging.getLogger()

INSTITUTION_NAME: str = 'Faber College'
LOGO_URL: str = 'https://freeiconshop.com/wp-content/uploads/edd/bank-flat.png'
CONFIG_PATH: str = 'verity-context.json'
WALLET_NAME: str = 'examplewallet1'
WALLET_KEY: str = 'examplewallet1'
QR_CODE_STRING: str = ""

context = Context
issuer_did: str = ''
issuer_verkey: str = ''

server: Server
port: int = 4000
handlers: Handlers = Handlers()
handlers.set_default_handler(default_handler)
handlers.add_handler('trust_ping', '1.0', noop)

routes: RouteTableDef = web.RouteTableDef()
cred_def_id_fix = "DGCGw4hAwb6ZL1JpmgPwCW:3:CL:173845:latest"
schema_id_fix = "DGCGw4hAwb6ZL1JpmgPwCW:2:CIS_Digital_Credentials:348.77.579"
rel_did = ''


async def example(loop):
    global context
    await setup(loop)
    relationship_did, qr_code_str = await create_relationship(loop)
    return relationship_did, qr_code_str


async def create_relationship(loop) -> str:
    global context
    global handlers

    # Relationship protocol has two steps
    # 1. create relationship key
    # 2. create invitation

    # Constructor for the Relationship API
    relationship: Relationship = Relationship()

    relationship_did = loop.create_future()
    thread_id = loop.create_future()

    spinner = make_spinner('Waiting to create relationship')  # Console spinner

    # handler for the response to the request to start the Connecting protocol.
    async def created_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == Relationship.CREATED:
            thread_id.set_result(message['~thread']['thid'])
            relationship_did.set_result(message['did'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(Relationship.MSG_FAMILY, Relationship.MSG_FAMILY_VERSION, created_handler)

    spinner.start()

    # starts the relationship protocol
    await relationship.create(context)
    thread_id = await thread_id
    relationship_did = await relationship_did

    # Step 2
    invitation = loop.create_future()
    qr_string = ""

    spinner = make_spinner('Waiting to create invitation')  # Console spinner

    # handler for the accept message sent when invitation is created
    async def invitation_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == Relationship.INVITATION:
            invite_url = message['inviteURL']
            qr = pyqrcode.create(invite_url)
            nonlocal qr_string
            qr_string = qr.png_as_base64_str(scale=5)
            # write QRCode to disk
            # Saving as png not required here
            qr.png("qrcode.png")
            if os.environ.get('HTTP_SERVER_URL'):
                print('Open the following URL in your browser and scan presented QR code')
                print(f'{ANSII_GREEN}{os.environ.get("HTTP_SERVER_URL")}/python-example-app/qrcode.html{ANSII_RESET}')
            else:
                print('QR code generated at: qrcode.png')
                print('Open this file and scan QR code to establish a connection')
            invitation.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    spinner.start()
    # note this overrides the handler for this message family! This is for demonstration purposes only.
    handlers.add_handler(Relationship.MSG_FAMILY, Relationship.MSG_FAMILY_VERSION, invitation_handler)

    relationship: Relationship = Relationship(relationship_did, thread_id)
    await relationship.connection_invitation(context)
    await invitation
    return relationship_did, qr_string  # return owning DID for the connection


async def create_connection(loop):
    global context
    global handlers

    # Connecting protocol is started from the Holder's side (ConnectMe)
    # by scanning the QR code containing connection invitation
    # Connection is established when the Holder accepts the connection on the device
    # i.e. when the RESPONSE_SENT control message is received

    connection = loop.create_future()

    spinner = make_spinner('Waiting to respond to connection')  # Console spinner

    # handler for messages in Connecting protocol
    async def connection_handler(msg_name, message):
        if msg_name == Connecting.REQUEST_RECEIVED:
            print()
            print_message(msg_name, message)
        elif msg_name == Connecting.RESPONSE_SENT:
            spinner.stop_and_persist('Done')
            print_message(msg_name, message)
            connection.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(Connecting.MSG_FAMILY, Connecting.MSG_FAMILY_VERSION, connection_handler)

    spinner.start()

    # waits for request
    try:
        await connection  # wait for response from verity application
    except Exception as e:
        print("CONNECTION USSSYEEEEEEEE, ", e)


async def write_ledger_schema(loop) -> str:
    # input parameters for schema
    schema_name = 'CIS_Digital_Credentials'
    schema_version = get_random_version()
    # schema_attrs = ['name', 'degree']
    schema_attrs = ['title', 'first_name', 'surname', 'date_of_birth',
                    'national_insurance_number', 'identity_assurance_level',
                    'uuid', 'user_photograph', 'user_photograph_hash']

    # constructor for the Write Schema protocol
    schema = WriteSchema(schema_name, schema_version, schema_attrs)

    first_step = loop.create_future()

    spinner = make_spinner('Waiting to write schema to ledger')  # Console spinner

    # handler for message received when schema is written
    async def schema_written_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == WriteSchema.STATUS:
            first_step.set_result(message['schemaId'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(WriteSchema.MSG_FAMILY, WriteSchema.MSG_FAMILY_VERSION, schema_written_handler)

    spinner.start()

    # request schema be written to ledger
    await schema.write(context)
    schema_id = await first_step  # wait for operation to be complete
    return schema_id  # returns ledger schema identifier


async def write_ledger_cred_def(loop, schema_id: str) -> str:
    # input parameters for cred definition
    cred_def_name = 'Trinity College Diplomas'
    cred_def_tag = 'latest'

    # constructor for the Write Credential Definition protocol
    cred_def = WriteCredentialDefinition(cred_def_name, schema_id, cred_def_tag)

    first_step = loop.create_future()

    spinner = make_spinner('Waiting to write cred def to ledger')  # Console spinner

    # handler for message received when schema is written
    async def cred_def_written_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == WriteCredentialDefinition.STATUS:
            first_step.set_result(message['credDefId'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(
        WriteCredentialDefinition.MSG_FAMILY,
        WriteCredentialDefinition.MSG_FAMILY_VERSION,
        cred_def_written_handler
    )

    spinner.start()

    # request the cred def be writen to ledger
    await cred_def.write(context)
    cred_def_id = await first_step  # wait for operation to be complete
    return cred_def_id  # returns ledger cred def identifier


async def ask_question(loop, for_did):
    print("IN ASK QUESTION")
    question_text = 'Hi Alice, how are you today?'
    question_detail = 'Checking up on you today.'
    valid_responses = ['Great!', 'Not so good.']

    question = CommittedAnswer(for_did, None, question_text, question_detail, valid_responses, True)
    first_step = loop.create_future()

    spinner = make_spinner('Waiting for Connect.Me to answer the question')  # Console spinner

    async def receive_answer(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == CommittedAnswer.ANSWER_GIVEN:
            first_step.set_result(None)
        else:
            print("ASK QUESTION NOT HANDLEDD")
            non_handled(f'Message name is not handled - {msg_name}', message)

    handlers.add_handler(CommittedAnswer.MSG_FAMILY, CommittedAnswer.MSG_FAMILY_VERSION, receive_answer)

    spinner.start()

    await question.ask(context)
    await first_step


async def issue_credential(loop, rel_did, cred_def_id):
    # TODO: Do API call to URS to fetch credentials data here and remove sample_data.json
    #  that require to pass UUID here from endpoint_handler
    with open('sample_data.json') as f:
        data = json.load(f)
    credential_name = 'CISDigitalCredential'
    credential_data = data

    # constructor for the Issue Credential protocol
    issue = IssueCredential(rel_did, None, cred_def_id, credential_data, credential_name, 0, True)

    offer_sent = loop.create_future()
    cred_sent = loop.create_future()
    spinner = make_spinner('Wait for Connect.me to accept the Credential Offer')  # Console spinner

    # handler for 'sent` message when the offer for credential is sent
    async def send_offer_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == IssueCredential.SENT:
            offer_sent.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(IssueCredential.MSG_FAMILY, IssueCredential.MSG_FAMILY_VERSION, send_offer_handler)

    spinner.start()
    # request that credential is offered
    await issue.offer_credential(context)
    await offer_sent  # wait for sending of offer to connect.me user

    # handler for 'sent` message when the credential is sent
    async def send_cred_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == IssueCredential.SENT:
            cred_sent.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(IssueCredential.MSG_FAMILY, IssueCredential.MSG_FAMILY_VERSION, send_cred_handler)

    spinner = make_spinner('waiting to send credential')  # Console spinner
    spinner.start()
    handlers.add_handler(IssueCredential.MSG_FAMILY, IssueCredential.MSG_FAMILY_VERSION, send_cred_handler)
    await cred_sent
    await asyncio.sleep(3)  # Wait a few seconds for the credential to arrive before sending the proof


async def request_proof(loop, for_did):
    global issuer_did

    # input parameters for request proof
    proof_name = 'Proof of Degree'
    proof_attrs = [
        {
            'name': 'name',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'degree',
            'restrictions': [{'issuer_did': issuer_did}]
        }
    ]

    # constructor for the Present Proof protocol
    proof = PresentProof(for_did, None, proof_name, proof_attrs)

    spinner = make_spinner('Waiting for proof presentation from Connect.me')  # Console spinner
    first_step = loop.create_future()

    # handler for the result of the proof presentation
    async def proof_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == PresentProof.PRESENTATION_RESULT:
            first_step.set_result(None)  # proof data contained inside `message`
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(PresentProof.MSG_FAMILY, PresentProof.MSG_FAMILY_VERSION, proof_handler)

    spinner.start()

    # request proof
    await proof.request(context)
    await first_step  # wait for connect.me user to present the requested proof


async def setup(loop):
    global context
    global issuer_did
    global schema_id_fix
    global cred_def_id_fix

    with open(CONFIG_PATH, 'r') as f:
        config = f.read()

    with open("test.json", 'r') as f:
        test_data = json.loads(f.read())

    if dict(test_data).get("contextAlreadyExist") == "true":
        pass
    else:
        if not config:
            context = await provision_agent()
        else:
            try:
                context = await Context.create_with_config(config)
            except WalletAlreadyOpenedError:
                await context.close_wallet()
        with open("test.json", 'w') as f:
            json.dump({"contextAlreadyExist": "true"}, f)

        with open('verity-context.json', 'w') as f:
            f.write(context.to_json())

    await update_webhook_endpoint()

    print_object(context.to_json(indent=2), '>>>', 'Context Used:')

    with open('verity-context.json', 'w') as f:
        f.write(context.to_json())

    await update_configs()
    await issuer_identifier(loop)

    if not issuer_did:
        print('\nIssuer DID is not created. Performing Issuer setup now...')
        await setup_issuer(loop)

    if dict(test_data).get("contextAlreadyExist") != "true":
        schema_id_fix = await write_ledger_schema(loop)
        print(schema_id_fix)

        cred_def_id_fix = await write_ledger_cred_def(loop, schema_id_fix)
        print(cred_def_id_fix)


async def provision_agent():
    global context

    # replace token value here it must be a valid JSON string, or fetch from OS environment
    # this is currently used by AWS linux instance
    token = '{"sponseeId": "Mastek", "sponsorId": "evernym-demo-sponsor", "nonce": "0Cx672Cpu1Ym6iucfr8SWBNszkBnaWr3", "timestamp": "2021-01-29T12:01:06.846458", "sig": "iGgohqAxg0V0lZ2ymz2ldmaj1Gr71WQCg7jIHhPhOE6DCuiHOP3u8wpvqGOqhLURlUI5PiFLu6dHvGRIZN26CA==", "sponsorVerKey": "BCHo16QAdnZtPxaEjGBPQEiohxF62LR3qVwce298g7Jf"}'

    # on local:
    # token = '{"sponseeId": "Mastek", "sponsorId": "evernym-demo-sponsor", "nonce": "0YClz7Xw76BbE0xtEsUuUPweKpvKCK9z", "timestamp": "2021-01-29T12:01:06.846458", "sig": "5Z8u98J2KUGW/CDY15pz9BdqI7XQvtHg8BPOOhd4rXKO6quMJVXxESVGtkbdGPXhN8W39pb+5CbEjApgv24lCQ==", "sponsorVerKey": "BCHo16QAdnZtPxaEjGBPQEiohxF62LR3qVwce298g7Jf"}'
    verity_url = "http://vas.pps.evernym.com/"
    print(f'Using Verity Application Endpoint Url: {ANSII_GREEN}{verity_url}{ANSII_RESET}')
    # create initial Context
    context = await Context.create(WALLET_NAME, WALLET_KEY, verity_url)

    # ask that an agent by provision (setup) and associated with created key pair
    try:
        response = await Provision(token).provision(context)
        return response
    except Exception as e:
        print(e)
        print('Provisioning failed! Likely causes:')
        print('- token not provided but Verity Endpoint requires it')
        print('- token provided but is invalid or expired')
        sys.exit(1)


async def update_webhook_endpoint():
    global context, port
    webhook_from_ctx: str = context.endpoint_url

    if not webhook_from_ctx:
        webhook_from_ctx = f'http://localhost:{port}'

    webhook = "http://ec2-3-16-28-53.us-east-2.compute.amazonaws.com/webhook"
    # for local use ngrok:
    # webhook = "http://8cb459f54391.ngrok.io/webhook"
    if not webhook:
        webhook = webhook_from_ctx

    print(f'Using Webhook: {ANSII_GREEN}{webhook}{ANSII_RESET}')
    context.endpoint_url = webhook

    # request that verity application use specified webhook endpoint
    await UpdateEndpoint().update(context)


async def update_configs():
    handlers.add_handler('update-configs', '0.6', noop)
    configs = UpdateConfigs(INSTITUTION_NAME, LOGO_URL)
    await configs.update(context)


async def issuer_identifier(loop):
    # constructor for the Issuer Setup protocol
    issuer_setup = IssuerSetup()

    first_step = loop.create_future()

    spinner = make_spinner('Waiting for current issuer DID')  # Console spinner

    # handler for current issuer identifier message
    async def current_identifier(msg_name, message):
        global issuer_did
        global issuer_verkey

        spinner.stop_and_persist('Done')

        if msg_name == IssuerSetup.PUBLIC_IDENTIFIER:
            issuer_did = message['did']
            issuer_verkey = message['verKey']
            first_step.set_result(None)
        elif msg_name == IssuerSetup.PROBLEM_REPORT:
            # Do nothing. Just means we need to write the keys to the ledger. Checked for in setup()
            first_step.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(IssuerSetup.MSG_FAMILY, IssuerSetup.MSG_FAMILY_VERSION, current_identifier)

    spinner.start()

    # query the current identifier
    await issuer_setup.current_public_identifier(context)
    await first_step  # wait for response from verity application


async def setup_issuer(loop):
    # constructor for the Issuer Setup protocol
    issuer_setup = IssuerSetup()

    first_step = loop.create_future()
    spinner = make_spinner('Waiting for setup to complete')  # Console spinner

    # handler for created issuer identifier message
    async def public_identifier_handler(msg_name, message):
        global issuer_did
        global issuer_verkey

        spinner.stop_and_persist('Done')

        if msg_name == IssuerSetup.PUBLIC_IDENTIFIER_CREATED:
            issuer_did = message['identifier']['did']
            issuer_verkey = message['identifier']['verKey']
            automated_registration = console_yes_no(f'Attempt automated registration via {ANSII_GREEN}https://selfserve.sovrin.org{ANSII_RESET}', True)
            if automated_registration:
                url = 'https://selfserve.sovrin.org/nym'
                payload = json.dumps({
                    'network': 'stagingnet',
                    'did': issuer_did,
                    'verkey': issuer_verkey,
                    'paymentaddr': ''
                })
                headers = {'Accept': 'application/json'}
                response = requests.request('POST', url, headers=headers, data=payload)
                if response.status_code != 200:
                    print('Something went wrong with contactig Sovrin portal')
                    print('Please add Issuer DID and Verkey to the ledger manually')
                    console_input('Press ENTER when DID is on ledger')
                else:
                    print(f'Got response from Sovrin portal: {ANSII_GREEN}{response.text}{ANSII_RESET}')
            else:
                print('Please add Issuer DID and Verkey to the ledger manually')
                console_input('Press ENTER when DID is on ledger')
            first_step.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}')

    # adds handler to the set of handlers
    handlers.add_handler(IssuerSetup.MSG_FAMILY, IssuerSetup.MSG_FAMILY_VERSION, public_identifier_handler)

    spinner.start()

    # request that issuer identifier be created
    await issuer_setup.create(context)

    await first_step  # wait for request to complete


async def unpack_message(context, message: bytes):
    """
    Extracts the message in the byte array that has been packaged and encrypted for a key that is locally held.
    Args:
        context (Context): an instance of the Context object initialized to a verity-application agent
        message (bytes): the raw message received from the verity-application agent
    Returns:
        dict: an unencrypted messages as a JSON object
    """
    jwe: bytes = await crypto.unpack_message(
        context.wallet_handle,
        message
    )
    message = json.loads(jwe.decode('utf-8'))['message']
    return json.loads(message)


async def endpoint_handler(request):
    global context
    try:
        m = await request.read()
        message = await unpack_message(context, m)

        await handlers.handle_message(context, m)

        if message['@type'] == 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response-sent':
            print("RESPOSNE SENTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTUUUUUUUUUUUUUUUUUUUUUU ", message)
            # print(message) Should contain myDID or
            # even relationship for did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/sent-response

        if message['@type'] == 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/sent-response':
            r_did = message['relationship']
            # DB.get(r_did)

            local_loop = asyncio.get_event_loop()
            relationship_did = message.get("relationship")

            await create_connection(local_loop)
            await ask_question(local_loop, relationship_did)
            await issue_credential(local_loop, relationship_did, cred_def_id_fix)
            # return web.Response(text='Success')

        return web.Response(text='Success')
    except Exception as e:
        traceback.print_exc()
        return web.Response(text=str(e))


async def api_issue_digital_identity(request):
    user_uuid = request.rel_url.query.get("uuid", "")
    if not user_uuid:
        response_data = {"status": 400, 'message': "Please pass uuid as query param", "user_status": "null"}
        return web.json_response(response_data, status=400)
    loop = asyncio.get_event_loop()
    rel_id, qr_string = await example(loop)
    # TODO: Update table here with
    #  1. uuid and rel_did
    #  2. uuid and qr_string
    image_source = "data:image/png;base64,{}".format(qr_string)
    # response = aiohttp_jinja2.render_template(
    #     "result.html", request=request,
    #     context={"image_source": image_source}
    # )
    # return response
    response_data = {"status": 200, 'qr_code-src': image_source}
    return web.json_response(response_data)


async def home(request):
    response = aiohttp_jinja2.render_template("index.html", request=request, context={})
    return response


async def fn_dw_identity_status(request):
    user_uuid = request.rel_url.query.get("uuid", "")
    if not user_uuid:
        response_data = {"status": 400, 'message': "Please pass uuid as query param", "user_status": "null"}
        return web.json_response(response_data, status=400)
    status_code = dbhelper.get_user_status_by_uuid(user_uuid)
    response_data = {"status": 200, 'user_status': status_code}
    return web.json_response(response_data)


my_web_app = web.Application()
my_web_app.add_routes(routes)

my_web_app.add_routes(
    [web.get('/', home),
     web.post('/webhook', endpoint_handler),
     web.get('/api_dw_identity_status', fn_dw_identity_status),
     web.get('/api_issue_digital_identity', api_issue_digital_identity)]
)

aiohttp_jinja2.setup(
        my_web_app, loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), "templates"))
    )

# if __name__ == '__main__':
#     web.run_app(my_web_app)
