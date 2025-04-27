import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  JoinColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Post } from '../../post/entities/post.entity';
import { ProjectVersion } from './project-version.entity';
import { Exclude } from 'class-transformer';

@Entity('projects')
export class Project {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.projects, { onDelete: 'CASCADE' })
  user: User;

  @Column()
  name: string;

  @Column({ nullable: true })
  description: string;

  // Removed: @Column({ type: 'jsonb' })
  // projectData: object;

  @Column({ default: false })
  isRendered: boolean;

  @Column({ default: 0 })
  renderCount: number;

  @OneToMany(() => Post, (post) => post.project)
  posts: Post[];

  @OneToMany(() => ProjectVersion, (version) => version.project)
  versions: ProjectVersion[];

  @ManyToOne(() => ProjectVersion)
  @JoinColumn({ name: 'currentVersionId' })
  currentVersion: ProjectVersion;

  @CreateDateColumn()
  createdAt: Date;

  @Exclude()
  @UpdateDateColumn()
  updatedAt: Date;

  @Exclude()
  @DeleteDateColumn()
  deletedAt?: Date;
}