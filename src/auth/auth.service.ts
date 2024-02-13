import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import { RegisterUserDto } from './dto/register-user.dto';

import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
    ) {}

    async register(registerUserDto: RegisterUserDto): Promise<User> {
        const user = await this.userRepository.findOne({
            where: { email: registerUserDto.email },
        });

        if (user) {
            // Thực hiện hành động khi email đã tồn tại
            console.log('email đã tồn tại');
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
        return !!user;
    }
}
