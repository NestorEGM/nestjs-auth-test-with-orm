import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
    ) { }

    async register({ password, email, name }) {
        const user = await this.usersService.findOneByEmail(email);

        if (user) {
            throw new BadRequestException('Este correo ya existe');
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        await this.usersService.create({
            name,
            email,
            password: hashedPassword,
        });

        return {
            message: 'Usuario creado',
        };
    }

    async login({ email, password }) {
        const user = await this.usersService.findOneByEmail(email);

        if (!user) {
            throw new UnauthorizedException('correo invalido');
        }

        const isValidPassword = await bcryptjs.compare(password, user.password)

        if (!isValidPassword) {
            throw new UnauthorizedException('contraseña invalida');
        }

        const payload = { email: user.email };

        const token = await this.jwtService.signAsync(payload);

        return {
            token,
            email: user.email,
        };
    }
}
