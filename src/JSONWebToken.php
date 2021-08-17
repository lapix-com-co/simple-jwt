<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

/**
 * @property string|null $alg Only available in recent created tokens.
 * @property string|null $kid Only available in recent created tokens.
 * @property string|null $sub
 * @property string|null $email
 * @property int|null $iat
 * @property int|null $exi
 * @property int|null $exp
 * @property int|null $nbf
 */
class JSONWebToken extends Token
{
}
