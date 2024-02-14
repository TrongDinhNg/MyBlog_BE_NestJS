import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import { RegisterUserDto } from './dto/register-user.dto';

import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import * as dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        private jwtService: JwtService,
    ) {}

    async register(registerUserDto: RegisterUserDto): Promise<User> {
        const user = await this.userRepository.findOne({
            where: { email: registerUserDto.email },
        });

        if (user) {
            // Thực hiện hành động khi email đã tồn tại
            console.log('user đã tồn tại');
        } else {
            // Thực hiện hành động khi email chưa tồn tại
            const hassPassword = await this.hashPassword(
                registerUserDto.password,
            );
            return await this.userRepository.save({
                ...registerUserDto,
                refresh_token: 'refresh_token',
                password: hassPassword,
            });
        }
    }

    async login(loginUserDto: LoginUserDto): Promise<any> {
        const user = await this.userRepository.findOne({
            where: { email: loginUserDto.email },
        });

        if (!user) {
            throw new HttpException(
                'Email is not exist!',
                HttpStatus.UNAUTHORIZED,
            );
        } else {
            // Thực hiện hành động khi email đã tồn tại
            console.log('user :', user);
            //check pass
            const isMatch = await bcrypt.compare(
                loginUserDto.password,
                user.password,
            );
            if (!isMatch) {
                throw new HttpException(
                    'Password is incorrect!',
                    HttpStatus.UNAUTHORIZED,
                );
            } else {
                console.log('Welcome ', user.firstName);
                const payload = { id: user.id, email: user.email };
                return this.generateToken(payload);
            }
        }
    }

    private async hashPassword(password: string): Promise<string> {
        const saltRounds = 10; //số vòng lặp băm

        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);

        return hashedPassword;
    }

    async checkUserExist(email: string): Promise<boolean> {
        const user = await this.userRepository.findOne({ where: { email } });
        return !!user; //chuyển user thành boolean
    }

    async refreshToken(refresh_token: string): Promise<any> {
        try {
            // 1. Verify refresh_token:
            const verify = await this.jwtService.verifyAsync(refresh_token, {
                secret: process.env.JWT_SECRET,
            });

            if (!verify) {
                throw new HttpException(
                    'Invalid refresh token',
                    HttpStatus.BAD_REQUEST,
                );
            }

            // 2. Check refresh_token existence in DB:
            const checkExistToken = await this.userRepository.findOneBy({
                email: verify.email,
                refresh_token,
            });

            if (!checkExistToken) {
                throw new HttpException(
                    'Refresh token not associated with any user',
                    HttpStatus.BAD_REQUEST,
                );
            }
            //3. Generate new access token and refresh token (if expired or blacklist)
            return await this.generateToken({
                id: verify.id,
                email: verify.email,
            });
        } catch (error) {
            throw new HttpException(
                'refresh_token is not valid',
                HttpStatus.BAD_REQUEST,
            );
        }
    }
    private async generateToken(payload: { id: number; email: string }) {
        const secret = process.env.JWT_SECRET;
        const access_token = await this.jwtService.signAsync(payload);
        const refresh_token = await this.jwtService.signAsync(payload, {
            secret: secret,
            expiresIn: '1h',
        });
        await this.userRepository.update(
            { email: payload.email },
            { refresh_token: refresh_token },
        );
        return { access_token, refresh_token };
    }
}
