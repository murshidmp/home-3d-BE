import {
    BeforeInsert,
    BeforeUpdate,
    Column,
    CreateDateColumn,
    Entity,
    PrimaryGeneratedColumn,
    UpdateDateColumn,

  } from 'typeorm';
  import { Role } from 'src/common/enums/roles';
   
  export enum AdminStatus {
    Active = 'active',
    Inactive = 'inactive',
    Invited = 'invited',
  }
   
  @Entity()
  export class Admin {
    @PrimaryGeneratedColumn()
    id!: number;
   
    @Column({ type: 'enum', enum: Role, default: Role.SubAdmin })
    admin_type!: Role;
   
    @Column({ type: 'varchar', nullable: false })
    name!: string;
   
    @Column({ type: 'varchar', nullable: false, unique: true, name: 'email' }) // Set column name as 'email'
    email!: string;
   
    @Column({ type: 'varchar', nullable: true })
    password?: string;
   
    @Column({ type: 'enum', enum: AdminStatus, default: AdminStatus.Invited })
    status!: AdminStatus;
   
    @CreateDateColumn({ type: 'timestamp' })
    created_at!: Date;
   
    @UpdateDateColumn({ type: 'timestamp' })
    updated_at!: Date;
   
    @Column({ type: 'varchar', nullable: true })
    resetPasswordToken?: string;
    
    @Column({ type: 'varchar', nullable: true })
    refreshToken?: string;
   
    @Column({ type: 'boolean', default: false })
    deleted!: boolean;
   
    // Custom setter for email property
    set _email(value: string) {
      this.email = value.toLowerCase();
    }
   
    // Custom getter for email property
    get _email(): string {
      return this.email;
    }
   
    @BeforeInsert()
    @BeforeUpdate()
    private updateEmailToLowercase() {
      if (this.email) {
        this.email = this.email.toLowerCase();
      }
    }
  }