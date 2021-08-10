<?php

require 'vendor/autoload.php';

use AmoCRM\Exceptions\AmoCRMApiException;
use AmoCRM\Models\AccountModel;
use AmoCRM\Models\ContactModel;
use AmoCRM\Models\CustomFieldsValues\ValueCollections\MultitextCustomFieldValueCollection;
use AmoCRM\Models\CustomFieldsValues\ValueCollections\TextCustomFieldValueCollection;
use AmoCRM\Models\CustomFieldsValues\MultitextCustomFieldValuesModel;
use AmoCRM\Models\CustomFieldsValues\ValueModels\MultitextCustomFieldValueModel;
use AmoCRM\Models\CustomFieldsValues\ValueModels\TextCustomFieldValueModel;
use AmoCRM\Models\CustomFieldsValues\TextCustomFieldValuesModel;
use AmoCRM\Exceptions\AmoCRMApiNoContentException;
use AmoCRM\Collections\LinksCollection;
use AmoCRM\Models\LeadModel;
use AmoCRM\Collections\CustomFieldsValuesCollection;
use AmoCRM\Filters\ContactsFilter;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Token\AccessToken;

Sentry\init(['dsn' => 'https://842fbeda697b4c0692e4e2ea03128a23@o951626.ingest.sentry.io/5900600' ]);

try {
    $name = $_REQUEST['name'];
    $tel = '+' . preg_replace('/\D/', '', $_REQUEST['tel']);
    $email = $_REQUEST['email'];

    if (!$name || !$tel || !$email) {
        return http_response_code(500);
    }

    GetResponseService::save($name, $email, $tel);

    $amoCrmService = new AmoCrmService();

    $amoCrmService->save($name, $email, $tel);
} catch (Exception $e) {
    return http_response_code(500);
}

class GetResponseService
{
    public static function save($name, $email, $tel)
    {
        $client = new GuzzleHttp\Client(['http_errors' => false]);

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        $response = $client->request(
            'POST',
            'https://api.getresponse.com/v3/contacts',
            [
                'headers' => [
                    'X-Auth-Token' => 'api-key yl9qr7p5o38hmds6wjdsemn305fvcmle',
                    'Content-Type' => 'application/json'
                ],
                'json' => [
                    'name' => $name,
                    'email' => $email,
                    'customFieldValues' => [
                        [
                            'customFieldId' => 'pcfXV2',
                            'value' => [$tel]
                        ]
                    ],
                    'campaign' => [
                        'campaignId' => '5sJLI'
                    ],
                    'ipAddress' => $ip
                ]
            ]
        );
    }
}

class AmoCrmService
{
    private $client;

    public function __construct()
    {
        $clientSecret = 'SRIP4O3OYeFBb1TmcUYyQOPG7JQ3b2vTcKAxT0DvRRYotrn2BQMRI0Jdw18iv5jO';
        $clientId = '8a288d3a-bd63-4efc-81e2-5efbdbedb231';
        $redirectUri = 'https://cursos.ultima.school/amocrm/callback';
        $code = 'def502001cc2a6edb812f465f0bdb0adc6638ebde795ed03e161c5b39153531f4c7279968861892bd6392cb82c5a97932d02aeea11895760cb1e9a84b00de1de5fb8d5fa0b935230e4cd8ba159955bb7ec99e0c33b8a9c2b3f79d0ab8b22ed18a3b2ec821c71a64a617fa698fbb7bdee52b31a4bab0f6ea0e3d2b9636bb85aa073b13776d6521304780dad62ae0ea0712c91842b951655f3a74434a10cdb5f440ca16d40219ddfdc2fa2c9930515434c07963b0db8b24926d263629ef022b266261830ba14a853097fbcc9945f88bc6190d55e6652cc9d0dd0f4a1644b9b83d97944fe739de74ec061008a91524a51f7926edb339e378fdcefe345ebf19c15ce8450fd473498c7be8749bc2e984a4b2150341c0d671028bee4becb8c7f746a2b504d1ba156537a666d9203368fc865bfc119982d1e265f2e6d58e54430a7cc41551213e1b71053f68c39a824a6b5fd0fae66e6a5b1ca8923891643a5aeb6f48086684fc602d6a305ca78128bcba4944729b91dafe47595f294cd787d87681c33fa6745ef26a62102ef4756fda745c7d4ae1ab2a53685848b62d111bd821f9b883b7b5fb8731695d5e9214e7e8d7836e1210bbdd363cc4938ea16fa6607703e1007cdcd7b7f0be2bba2b7583318b16876a86cd02c5fdba761';
        $baseDomain = 'ultimaschool.amocrm.com';

        $apiClient = new \AmoCRM\Client\AmoCRMApiClient($clientId, $clientSecret, $redirectUri);
        $apiClient->setAccountBaseDomain($baseDomain);

        $accessToken = file_get_contents('amocrm.txt');

        if ($accessToken) {
            $accessToken = json_decode($accessToken, true);

            $accessToken = new AccessToken([
                'access_token' => $accessToken['accessToken'],
                'refresh_token' => $accessToken['refreshToken'],
                'expires' => $accessToken['expires'],
                'baseDomain' => $accessToken['baseDomain'],
            ]);
        } else {
            $accessToken = $apiClient->getOAuthClient()->getAccessTokenByCode($code);

            file_put_contents('amocrm.txt', json_encode([
                'accessToken' => $accessToken->getToken(),
                'refreshToken' => $accessToken->getRefreshToken(),
                'expires' => $accessToken->getExpires(),
                'baseDomain' => $baseDomain
            ]));
        }

        $apiClient->setAccessToken($accessToken)
                ->setAccountBaseDomain('ultimaschool.amocrm.com')
                ->onAccessTokenRefresh(
                    function (AccessTokenInterface $accessToken, string $baseDomain) {
                        file_put_contents('amocrm.txt', json_encode([
                            'accessToken' => $accessToken->getToken(),
                            'refreshToken' => $accessToken->getRefreshToken(),
                            'expires' => $accessToken->getExpires(),
                            'baseDomain' => $baseDomain,
                        ]));
                    }
                );

        $this->client = $apiClient;
    }

    public function save($name, $email, $tel)
    {
        $contact = $this->storeOrGetContact($name, $email, $tel);

        $utms = [];
        $ref = $_SERVER['HTTP_REFERER'];
        $url = parse_url($ref);

        if (isset($url['query'])) {
            parse_str($url['query'], $utms);
        }

        $lead = $this->createLead('Digital Marketing', [
            1414839 => isset($utms['utm_medium']) ? $utms['utm_medium'] : '',
            1414841 => isset($utms['utm_term']) ? $utms['utm_term'] : '',
            1414843 => isset($utms['utm_campaign']) ? $utms['utm_campaign'] : '',
            1414845 => isset($utms['utm_content']) ? $utms['utm_content'] : '',
            1414849 => isset($utms['utm_name']) ? $utms['utm_name'] : '',
            1414851 => isset($utms['utm_source']) ? $utms['utm_source'] : '',
            1499105 => $ref,
        ]);

        $links = new LinksCollection();

        $links->add($contact);
            
        $this->client->leads()->link($lead, $links);
    }

    private function storeOrGetContact($name, $email, $tel)
    {
        $filter = new ContactsFilter();
        $filter->setQuery($email);

        try {
            $contacts = $this->client->contacts()->get($filter);
        } catch (AmoCRMApiNoContentException $e) {
            $contacts = null;
        }

        if (isset($contacts[0])) {
            return $contacts[0];
        } else {
            $contact = new ContactModel();
            $contact->setName($name);

            $contactsCustomFieldsValues = new CustomFieldsValuesCollection();

            $telField = (new TextCustomFieldValuesModel())->setFieldCode('PHONE');
            $telField->setValues(
                (new TextCustomFieldValueCollection())
                    ->add(
                        (new TextCustomFieldValueModel())
                            ->setValue($tel)
                    )
            );
            $contactsCustomFieldsValues->add($telField);

            $emailField = (new TextCustomFieldValuesModel())->setFieldCode('EMAIL');
            $emailField->setValues(
                (new TextCustomFieldValueCollection())
                    ->add(
                        (new TextCustomFieldValueModel())
                            ->setValue($email)
                    )
            );
            $contactsCustomFieldsValues->add($emailField);

            $contact->setCustomFieldsValues($contactsCustomFieldsValues);

            $contactModel = $this->client->contacts()->addOne($contact);

            return $contactModel;
        }
    }

    private function createLead($name, $fields)
    {
        $lead = new LeadModel();

        $leadCustomFieldsValues = new CustomFieldsValuesCollection();

        foreach ($fields as $key => $value) {
            $textCustomFieldValueModel = new TextCustomFieldValuesModel();
            $textCustomFieldValueModel->setFieldId($key);
            $textCustomFieldValueModel->setValues(
                (new TextCustomFieldValueCollection())
                    ->add((new TextCustomFieldValueModel())->setValue($value))
            );
            $leadCustomFieldsValues->add($textCustomFieldValueModel);
        }

        $lead->setCustomFieldsValues($leadCustomFieldsValues);

        $lead->setName($name);

        $lead->setPipelineId(4490092)->setStatusId(41515582);

        $lead = $this->client->leads()->addOne($lead);

        return $lead;
    }
}
